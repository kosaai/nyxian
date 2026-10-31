/*
 SPDX-License-Identifier: LicenseRef-EPSL-1.1

 Copyright (C) 2025 - 2026 emexlab

 This file is part of Nyxian.

 Licensed under the emexLabs Public Source License, version 1.1
 (EPSL 1.1).

 Private use and modification are permitted under the license.
 Redistribution of source or binaries, modified or unmodified,
 requires prior written permission from emexLabs.

 External deployment is subject to the source-availability
 requirements and other conditions of the license.

 Provided "AS IS", without warranty, to the extent permitted by law.

 See LICENSE for the full license terms.
*/

import Foundation
import Network
import Security

/// Phase 2: MCP server core.
///
/// Serves the Model Context Protocol over Streamable HTTP on port 8377:
/// `POST /mcp` accepts JSON-RPC 2.0 messages (`initialize`, `tools/list`,
/// `tools/call`, `ping`) protected by a Bearer token, and `GET /health` stays
/// open for connectivity checks.
///
/// All file-system access is plain `FileManager` over
/// `<Documents>/Projects/<project>` — the same location `NXBootstrap`
/// exposes as `projectsURL`. No `NXDocument` involvement: the editor's
/// document machinery is intentionally bypassed, per the agreed design.
///
/// Path safety: every tool argument is normalized and then verified to keep
/// the resolved URL inside the project directory (standardized path *and*
/// symlink-resolved path both checked). The `Config/` directory — build
/// configuration — is refused for writes/deletes unless the caller passes
/// `allow_config: true` explicitly.
final class NXMCPServer: NSObject {

    /// Port the server binds to. Tailscale traffic is delivered straight to
    /// it, so it stays fixed on every device.
    static let port: NWEndpoint.Port = 8377

    /// Shared instance. Reuse it when wiring startup so a second instance
    /// never fights over the port.
    static let shared = NXMCPServer()

    /// Hard ceiling for one HTTP body (MCP request), protecting memory.
    static let maxBodyBytes: Int = 10 * 1024 * 1024

    /// Ceiling for a single `nx_write_file` payload.
    static let maxWriteBytes: Int = 5 * 1024 * 1024

    /// Protocol versions this server answers with during `initialize`.
    private static let supportedProtocolVersions = ["2025-06-18", "2025-03-26", "2024-11-05"]

    /// Fallback protocol version when the client asks for something unknown.
    private static let latestProtocolVersion = "2025-06-18"

    /// Settings contract shared with ManagementViewController (SuperSlot
    /// target). Both targets compile independently — no imports possible —
    /// so the contract is plain strings. Keep in sync with the copy in
    /// ManagementViewController.swift.
    enum Contract {
        static let enabledKey = "NXMCPServer.Enabled"
        static let runningKey = "NXMCPServer.Running"
        static let enabledChangedNotification = "NXMCPServerEnabledChanged"
        static let stateChangedNotification = "NXMCPServerStateChanged"
        static let keychainService = "app.nyxian.mcp-server"
        static let keychainAccount = "auth-token"
        static let port = 8377
        /// Pre-Keychain storage, migrated once then removed.
        static let legacyTokenDefaultsKey = "NXMCPServer.AuthToken"
    }

    private var listener: NWListener?
    private let queue = DispatchQueue(label: "com.nyxian.mcpserver")

    /// True while the listener is ready to accept connections.
    private(set) var isRunning: Bool = false

    /// Explicit token override (future Keychain/Settings wiring). When nil,
    /// the token falls back to UserDefaults, generating one on first run.
    var authToken: String?

    private lazy var isoFormatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()

    private override init() {
        super.init()
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(enabledChanged),
            name: Notification.Name(Contract.enabledChangedNotification),
            object: nil
        )
        // Materialize the token now so Settings can display it before the
        // first request ever arrives.
        _ = currentToken()
    }

    // MARK: - Lifecycle

    /// Startup entry point: starts only if the user toggle (default: on) is
    /// enabled. Called after Bootstrap finishes.
    func startIfEnabled() {
        if UserDefaults.standard.object(forKey: Contract.enabledKey) as? Bool ?? true {
            start()
        } else {
            NSLog("[NXMCPServer] disabled by user, not starting")
        }
    }

    /// Binds the listener and begins accepting connections.
    ///
    /// Safe to call more than once; a second call while running is ignored.
    func start() {
        queue.async { [weak self] in
            guard let self, !self.isRunning else { return }

            let parameters = NWParameters.tcp
            // Transport security is delegated to Tailscale; no TLS here.
            parameters.allowLocalEndpointReuse = true

            guard let listener = try? NWListener(using: parameters, on: NXMCPServer.port) else {
                NSLog("[NXMCPServer] failed to create listener on port %d", Int(NXMCPServer.port.rawValue))
                return
            }

            listener.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    self.setRunning(true)
                    NSLog("[NXMCPServer] listening on port %d", Int(NXMCPServer.port.rawValue))
                case .failed(let error):
                    NSLog("[NXMCPServer] listener failed: %@", error.localizedDescription)
                    self.stopLocked()
                case .cancelled:
                    NSLog("[NXMCPServer] listener cancelled")
                    self.setRunning(false)
                default:
                    break
                }
            }

            listener.newConnectionHandler = { [weak self] connection in
                self?.accept(connection)
            }

            listener.start(queue: self.queue)
            self.listener = listener
        }
    }

    /// Stops accepting and tears down the listener.
    func stop() {
        queue.async { [weak self] in
            self?.stopLocked()
        }
    }

    private func stopLocked() {
        listener?.cancel()
        listener = nil
        setRunning(false)
    }

    /// Single writer for `isRunning`: persists the state for the Settings UI
    /// and posts a change notification (on main, for UIKit observers).
    private func setRunning(_ running: Bool) {
        guard isRunning != running else { return }
        isRunning = running
        UserDefaults.standard.set(running, forKey: Contract.runningKey)
        DispatchQueue.main.async {
            NotificationCenter.default.post(
                name: Notification.Name(Contract.stateChangedNotification),
                object: nil
            )
        }
    }

    /// Settings toggle: reacts to `enabledChangedNotification` by starting or
    /// stopping the listener on the server queue.
    @objc private func enabledChanged() {
        let enabled = UserDefaults.standard.object(forKey: Contract.enabledKey) as? Bool ?? true
        if enabled {
            start()
        } else {
            stop()
        }
    }

    // MARK: - Authentication

    /// Resolves the active Bearer token: explicit override, then Keychain,
    /// then a freshly generated one persisted to Keychain. A token left over
    /// from the pre-Keychain UserDefaults storage is migrated once.
    private func currentToken() -> String? {
        if let token = authToken, !token.isEmpty {
            return token
        }
        if let token = Self.keychainRead(), !token.isEmpty {
            return token
        }
        if let legacy = UserDefaults.standard.string(forKey: Self.Contract.legacyTokenDefaultsKey), !legacy.isEmpty {
            Self.keychainWrite(legacy)
            UserDefaults.standard.removeObject(forKey: Self.Contract.legacyTokenDefaultsKey)
            return legacy
        }
        var bytes = [UInt8](repeating: 0, count: 32)
        for index in bytes.indices {
            bytes[index] = UInt8.random(in: .min ... .max)
        }
        let token = Data(bytes).base64EncodedString()
        Self.keychainWrite(token)
        return token
    }

    // MARK: - Keychain

    private static var keychainBase: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Contract.keychainService,
            kSecAttrAccount as String: Contract.keychainAccount
        ]
    }

    private static func keychainRead() -> String? {
        var query = keychainBase
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else {
            if status != errSecItemNotFound {
                NSLog("[NXMCPServer] keychain read failed: %d", Int(status))
            }
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    @discardableResult
    private static func keychainWrite(_ token: String) -> Bool {
        guard let data = token.data(using: .utf8) else { return false }
        let update = [kSecValueData as String: data]
        var status = SecItemUpdate(keychainBase as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var add = keychainBase
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
            status = SecItemAdd(add as CFDictionary, nil)
        }
        if status != errSecSuccess {
            NSLog("[NXMCPServer] keychain write failed: %d", Int(status))
            return false
        }
        return true
    }

    /// Constant-time comparison of the `Authorization` header against
    /// `Bearer <token>`.
    private func isAuthorized(_ header: String?) -> Bool {
        guard let header, let token = currentToken() else { return false }
        let expected = "Bearer " + token
        guard header.utf8.count == expected.utf8.count else { return false }
        var diff: UInt8 = 0
        for (lhs, rhs) in zip(header.utf8, expected.utf8) {
            diff |= lhs ^ rhs
        }
        return diff == 0
    }

    // MARK: - Connections

    private func accept(_ connection: NWConnection) {
        connection.start(queue: queue)
        receive(on: connection, buffer: Data())
    }

    /// Drains bytes until the request head plus declared body are complete,
    /// or the connection stalls. Requests declaring more than
    /// `maxBodyBytes` get a 413 immediately.
    private func receive(on connection: NWConnection, buffer: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self else {
                connection.cancel()
                return
            }

            var buffer = buffer
            if let data {
                buffer.append(data)
            }

            if let declared = NXHTTPServerRequest.declaredContentLength(in: buffer),
               declared > NXMCPServer.maxBodyBytes {
                self.send(
                    NXHTTPServerResponse(status: 413, contentType: "application/json",
                                         body: Data("{\"error\":\"payload_too_large\"}".utf8)),
                    on: connection
                )
                return
            }

            if let request = NXHTTPServerRequest(data: buffer) {
                self.respond(to: request, on: connection)
                return
            }

            if isComplete || error != nil {
                connection.cancel()
                return
            }

            self.receive(on: connection, buffer: buffer)
        }
    }

    // MARK: - HTTP routing

    private func respond(to request: NXHTTPServerRequest, on connection: NWConnection) {
        switch (request.method, request.path) {
        case ("GET", "/health"):
            let body = (try? JSONSerialization.data(withJSONObject: [
                "status": "ok",
                "server": "nx-mcp-server",
                "protocolVersion": 1
            ])) ?? Data("{\"status\":\"ok\"}".utf8)
            send(NXHTTPServerResponse(status: 200, contentType: "application/json", body: body), on: connection)

        case ("POST", "/mcp"):
            guard isAuthorized(request.headers["authorization"]) else {
                send(NXHTTPServerResponse(status: 401, contentType: "application/json",
                                          body: Data("{\"error\":\"unauthorized\"}".utf8),
                                          extraHeaders: ["WWW-Authenticate": "Bearer"]),
                     on: connection)
                return
            }

            guard let payload = handleJSONRPCPayload(request.body) else {
                // Batch of notifications: acknowledged without a body.
                send(NXHTTPServerResponse(status: 202, contentType: "application/json", body: Data()), on: connection)
                return
            }
            send(NXHTTPServerResponse(status: 200, contentType: "application/json", body: payload), on: connection)

        case ("GET", "/mcp"):
            // Streamable HTTP: clients POST; GET would open an SSE stream,
            // which this server does not offer.
            send(NXHTTPServerResponse(status: 405, contentType: "application/json",
                                      body: Data("{\"error\":\"method_not_allowed\",\"hint\":\"POST /mcp\"}".utf8),
                                      extraHeaders: ["Allow": "POST"]),
                 on: connection)

        default:
            send(NXHTTPServerResponse(status: 404, contentType: "application/json",
                                      body: Data("{\"error\":\"not_found\"}".utf8)),
                 on: connection)
        }
    }

    private func send(_ response: NXHTTPServerResponse, on connection: NWConnection) {
        connection.send(content: response.render, completion: .contentProcessed { _ in
            connection.cancel()
        })
    }

    // MARK: - JSON-RPC 2.0

    /// Returns the serialized response, or nil when every message was a
    /// notification (nothing to answer).
    private func handleJSONRPCPayload(_ payload: Data) -> Data? {
        let parsed: Any
        do {
            parsed = try JSONSerialization.jsonObject(with: payload, options: [])
        } catch {
            return serialize(errorResponse(id: NSNull(), code: -32700, message: "Parse error"))
        }

        if let batch = parsed as? [Any] {
            guard !batch.isEmpty else {
                return serialize(errorResponse(id: NSNull(), code: -32600, message: "Invalid Request: empty batch"))
            }
            var responses: [Any] = []
            for item in batch {
                if let response = handleRPCObject(item) {
                    responses.append(response)
                }
            }
            guard !responses.isEmpty else { return nil }
            return serialize(responses)
        }

        guard let response = handleRPCObject(parsed) else { return nil }
        return serialize(response)
    }

    /// Handles one JSON-RPC message. Returns nil for notifications.
    private func handleRPCObject(_ object: Any) -> Any? {
        guard let message = object as? [String: Any],
              message["jsonrpc"] as? String == "2.0",
              let method = message["method"] as? String
        else {
            return errorResponse(id: NSNull(), code: -32600, message: "Invalid Request")
        }

        // Notifications (no `id`) and MCP lifecycle notifications get no body.
        guard message.keys.contains("id") else { return nil }

        let id = message["id"] ?? NSNull()
        let params = message["params"] as? [String: Any] ?? [:]

        if method.hasPrefix("notifications/") {
            return nil
        }

        switch method {
        case "initialize":
            let requested = params["protocolVersion"] as? String
            let version: String
            if let requested, NXMCPServer.supportedProtocolVersions.contains(requested) {
                version = requested
            } else {
                version = NXMCPServer.latestProtocolVersion
            }
            let result: [String: Any] = [
                "protocolVersion": version,
                "capabilities": ["tools": ["listChanged": false]],
                "serverInfo": [
                    "name": "nyxian-mcp",
                    "title": "Nyxian MCP Server",
                    "version": "0.2.0"
                ],
                "instructions": """
                Remote access to Nyxian projects on iOS. All tools take a \
                `project` id from nx_list_projects and paths relative to that \
                project root. Writes and deletes inside `Config/` require \
                `allow_config: true`.
                """
            ]
            return successResponse(id: id, result: result)

        case "ping":
            return successResponse(id: id, result: [:])

        case "tools/list":
            return successResponse(id: id, result: ["tools": toolDefinitions])

        case "tools/call":
            guard let name = params["name"] as? String else {
                return errorResponse(id: id, code: -32602, message: "Invalid params: missing tool name")
            }
            let arguments = params["arguments"] as? [String: Any] ?? [:]
            return successResponse(id: id, result: callTool(name, arguments: arguments))

        default:
            return errorResponse(id: id, code: -32601, message: "Method not found: \(method)")
        }
    }

    private func successResponse(id: Any, result: [String: Any]) -> [String: Any] {
        ["jsonrpc": "2.0", "id": id, "result": result]
    }

    private func errorResponse(id: Any, code: Int, message: String) -> [String: Any] {
        ["jsonrpc": "2.0", "id": id, "error": ["code": code, "message": message]]
    }

    private func serialize(_ object: Any) -> Data? {
        try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }
}

// MARK: - MCP tools

extension NXMCPServer {

    /// Tool error surfaced to the client as an `isError` result, not a
    /// protocol error — expected conditions (missing file, bad path) are
    /// tool-level outcomes.
    struct NXToolError: Error {
        let message: String
        init(_ message: String) { self.message = message }
    }

    /// `tools/list` payload: the six tools plus their input schemas.
    var toolDefinitions: [[String: Any]] {
        [
            [
                "name": "nx_list_projects",
                "description": "List Nyxian projects available on the device, with display names read from each project's Config/Project.plist.",
                "inputSchema": ["type": "object", "properties": [String: Any](), "additionalProperties": false]
            ],
            [
                "name": "nx_list_files",
                "description": "List files and directories inside a project (optionally recursive). Paths are relative to the project root.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "project": ["type": "string", "description": "Project id from nx_list_projects."],
                        "path": ["type": "string", "description": "Relative subpath; empty lists the project root."],
                        "recursive": ["type": "boolean", "description": "Descend into subdirectories. Default false."]
                    ],
                    "required": ["project"],
                    "additionalProperties": false
                ]
            ],
            [
                "name": "nx_read_file",
                "description": "Read a UTF-8 text file from a project. Returns content plus size and last-modified time.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "project": ["type": "string", "description": "Project id from nx_list_projects."],
                        "path": ["type": "string", "description": "Relative file path inside the project."],
                        "max_bytes": ["type": "integer", "description": "Truncation limit in bytes. Default 524288, max 2097152."]
                    ],
                    "required": ["project", "path"],
                    "additionalProperties": false
                ]
            ],
            [
                "name": "nx_write_file",
                "description": "Create or overwrite a text file in a project (atomic write). Writes inside Config/ need allow_config: true.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "project": ["type": "string", "description": "Project id from nx_list_projects."],
                        "path": ["type": "string", "description": "Relative file path inside the project."],
                        "content": ["type": "string", "description": "Full new file content (UTF-8, max 5 MB)."],
                        "create_dirs": ["type": "boolean", "description": "Create missing parent directories. Default true."],
                        "allow_config": ["type": "boolean", "description": "Permit writing under Config/. Default false."]
                    ],
                    "required": ["project", "path", "content"],
                    "additionalProperties": false
                ]
            ],
            [
                "name": "nx_delete_file",
                "description": "Delete a file or directory in a project. Directories need recursive: true. Deleting Config/ needs allow_config: true; the project root itself cannot be deleted.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "project": ["type": "string", "description": "Project id from nx_list_projects."],
                        "path": ["type": "string", "description": "Relative path inside the project."],
                        "recursive": ["type": "boolean", "description": "Required to delete a directory. Default false."],
                        "allow_config": ["type": "boolean", "description": "Permit deleting under Config/. Default false."]
                    ],
                    "required": ["project", "path"],
                    "additionalProperties": false
                ]
            ],
            [
                "name": "nx_search",
                "description": "Search for a text substring across a project's text files. Returns matching lines with file and line number.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "project": ["type": "string", "description": "Project id from nx_list_projects."],
                        "query": ["type": "string", "description": "Substring to search for."],
                        "path": ["type": "string", "description": "Relative subpath to search within. Default: whole project."],
                        "extension": ["type": "string", "description": "Only files with this extension, e.g. \"swift\"."],
                        "case_sensitive": ["type": "boolean", "description": "Default false."],
                        "max_results": ["type": "integer", "description": "Cap on returned matches. Default 100, max 1000."]
                    ],
                    "required": ["project", "query"],
                    "additionalProperties": false
                ]
            ]
        ]
    }

    /// Dispatches `tools/call`; tool failures become `isError` results.
    func callTool(_ name: String, arguments: [String: Any]) -> [String: Any] {
        do {
            let result: [String: Any]
            switch name {
            case "nx_list_projects":
                result = try toolListProjects()
            case "nx_list_files":
                result = try toolListFiles(arguments)
            case "nx_read_file":
                result = try toolReadFile(arguments)
            case "nx_write_file":
                result = try toolWriteFile(arguments)
            case "nx_delete_file":
                result = try toolDeleteFile(arguments)
            case "nx_search":
                result = try toolSearch(arguments)
            default:
                return toolTextResult("Unknown tool: \(name)", isError: true)
            }
            guard let data = try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]),
                  let text = String(data: data, encoding: .utf8) else {
                return toolTextResult("Tool result was not serializable.", isError: true)
            }
            return toolTextResult(text, isError: false)
        } catch let error as NXToolError {
            return toolTextResult(error.message, isError: true)
        } catch {
            return toolTextResult("Unexpected error: \(error.localizedDescription)", isError: true)
        }
    }

    private func toolTextResult(_ text: String, isError: Bool) -> [String: Any] {
        ["content": [["type": "text", "text": text]], "isError": isError]
    }

    // MARK: nx_list_projects

    private func toolListProjects() throws -> [String: Any] {
        let root = try projectsRootURL()
        let fm = FileManager.default
        let ids = (try? fm.contentsOfDirectory(atPath: root.path))?.sorted() ?? []

        var projects: [[String: Any]] = []
        for id in ids {
            guard !id.hasPrefix(".") else { continue }
            let dir = root.appendingPathComponent(id, isDirectory: true)
            var isDirectory: ObjCBool = false
            guard fm.fileExists(atPath: dir.path, isDirectory: &isDirectory), isDirectory.boolValue else {
                continue
            }
            var entry: [String: Any] = ["id": id]
            if let name = projectName(at: dir) {
                entry["name"] = name
            }
            if let modified = (try? fm.attributesOfItem(atPath: dir.path))?[.modificationDate] as? Date {
                entry["modified"] = isoFormatter.string(from: modified)
            }
            projects.append(entry)
        }

        return ["projects": projects, "count": projects.count]
    }

    /// Best-effort display name: `NXDisplayName` in Config/Project.plist,
    /// falling back to `NXExecutable`, then the directory name.
    private func projectName(at directory: URL) -> String? {
        let plistURL = directory.appendingPathComponent("Config/Project.plist")
        guard let data = try? Data(contentsOf: plistURL),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        else {
            return nil
        }
        if let name = plist["NXDisplayName"] as? String, !name.isEmpty { return name }
        if let executable = plist["NXExecutable"] as? String, !executable.isEmpty { return executable }
        return nil
    }

    // MARK: nx_list_files

    private func toolListFiles(_ args: [String: Any]) throws -> [String: Any] {
        let project = try projectURL(try requireString(args, "project"))
        let relative = try optionalString(args, "path") ?? ""
        let recursive = try optionalBool(args, "recursive") ?? false
        let directory = try resolvePath(relative, in: project, allowProjectRoot: true)

        let fm = FileManager.default
        var isDirectory: ObjCBool = false
        guard fm.fileExists(atPath: directory.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw NXToolError("not a directory: \(relative.isEmpty ? "/" : relative)")
        }

        let projectPrefix = project.resolvingSymlinksInPath().path + "/"
        var entries: [[String: Any]] = []
        var truncated = false

        if recursive {
            let keys: [URLResourceKey] = [.isDirectoryKey, .fileSizeKey, .contentModificationDateKey]
            guard let enumerator = fm.enumerator(at: directory, includingPropertiesForKeys: keys, options: []) else {
                throw NXToolError("could not enumerate directory")
            }
            for case let url as URL in enumerator {
                if entries.count >= 5000 {
                    truncated = true
                    break
                }
                let relativePath = relativePathString(of: url, projectPath: projectPrefix)
                guard let entry = fileEntry(for: url, relativePath: relativePath) else { continue }
                entries.append(entry)
            }
        } else {
            let children = (try? fm.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil, options: [])) ?? []
            for url in children.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
                let relativePath = relativePathString(of: url, projectPath: projectPrefix)
                guard let entry = fileEntry(for: url, relativePath: relativePath) else { continue }
                entries.append(entry)
            }
        }

        entries.sort { ($0["path"] as? String ?? "") < ($1["path"] as? String ?? "") }
        return ["entries": entries, "count": entries.count, "truncated": truncated]
    }

    private func fileEntry(for url: URL, relativePath: String) -> [String: Any]? {
        let values = try? url.resourceValues(forKeys: [.isDirectoryKey, .fileSizeKey, .contentModificationDateKey])
        guard let values else { return nil }
        let isDirectory = values.isDirectory ?? false
        var entry: [String: Any] = [
            "path": relativePath,
            "name": url.lastPathComponent,
            "type": isDirectory ? "directory" : "file"
        ]
        if !isDirectory, let size = values.fileSize {
            entry["size"] = size
        }
        if let modified = values.contentModificationDate {
            entry["modified"] = isoFormatter.string(from: modified)
        }
        return entry
    }

    private func relativePathString(of url: URL, projectPath: String) -> String {
        let path = url.standardizedFileURL.resolvingSymlinksInPath().path
        if path.hasPrefix(projectPath) {
            return String(path.dropFirst(projectPath.count))
        }
        return url.lastPathComponent
    }

    // MARK: nx_read_file

    private func toolReadFile(_ args: [String: Any]) throws -> [String: Any] {
        let project = try projectURL(try requireString(args, "project"))
        let relative = try requireString(args, "path")
        let requestedLimit = try optionalInt(args, "max_bytes") ?? 524_288
        let limit = min(max(requestedLimit, 1), 2 * 1024 * 1024)

        let url = try resolvePath(relative, in: project, allowProjectRoot: false)
        let fm = FileManager.default
        guard fm.fileExists(atPath: url.path) else {
            throw NXToolError("file not found: \(relative)")
        }

        let attributes = (try? fm.attributesOfItem(atPath: url.path)) ?? [:]
        let size = (attributes[.size] as? NSNumber)?.intValue ?? 0
        let modified = attributes[.modificationDate] as? Date

        guard let data = try? Data(contentsOf: url, options: .mappedIfSafe) else {
            throw NXToolError("could not read: \(relative)")
        }

        let truncated = data.count > limit
        let slice = truncated ? data.prefix(limit) : data[...]
        guard let content = String(data: Data(slice), encoding: .utf8) else {
            throw NXToolError("binary or non-UTF-8 file (\(size) bytes): \(relative)")
        }

        var result: [String: Any] = [
            "path": relative,
            "size": size,
            "content": content,
            "truncated": truncated
        ]
        if let modified {
            result["modified"] = isoFormatter.string(from: modified)
        }
        return result
    }

    // MARK: nx_write_file

    private func toolWriteFile(_ args: [String: Any]) throws -> [String: Any] {
        let project = try projectURL(try requireString(args, "project"))
        let relative = try requireString(args, "path")
        let content = try requireString(args, "content", allowEmpty: true)
        let createDirs = try optionalBool(args, "create_dirs") ?? true
        let allowConfig = try optionalBool(args, "allow_config") ?? false

        guard let payload = content.data(using: .utf8) else {
            throw NXToolError("content is not valid UTF-8")
        }
        guard payload.count <= NXMCPServer.maxWriteBytes else {
            throw NXToolError("content exceeds \(NXMCPServer.maxWriteBytes) bytes")
        }

        let url = try resolvePath(relative, in: project, allowProjectRoot: false)
        try guardConfig(relative: relative, allowed: allowConfig)

        let fm = FileManager.default
        let parent = url.deletingLastPathComponent()
        var parentIsDirectory: ObjCBool = false
        let parentExists = fm.fileExists(atPath: parent.path, isDirectory: &parentIsDirectory)
        if parentExists {
            guard parentIsDirectory.boolValue else {
                throw NXToolError("parent path is not a directory: \(relative)")
            }
        } else if createDirs {
            do {
                try fm.createDirectory(at: parent, withIntermediateDirectories: true)
            } catch {
                throw NXToolError("could not create directories: \(error.localizedDescription)")
            }
        } else {
            throw NXToolError("parent directory does not exist: \(relative)")
        }

        let existedBefore = fm.fileExists(atPath: url.path)
        do {
            try payload.write(to: url, options: .atomic)
        } catch {
            throw NXToolError("write failed: \(error.localizedDescription)")
        }

        let finalAttributes = (try? fm.attributesOfItem(atPath: url.path)) ?? [:]
        let size = (finalAttributes[.size] as? NSNumber)?.intValue ?? payload.count
        let modified = finalAttributes[.modificationDate] as? Date
        var result: [String: Any] = [
            "path": relative,
            "bytes_written": size,
            "created": !existedBefore
        ]
        if let modified {
            result["modified"] = isoFormatter.string(from: modified)
        }
        return result
    }

    // MARK: nx_delete_file

    private func toolDeleteFile(_ args: [String: Any]) throws -> [String: Any] {
        let project = try projectURL(try requireString(args, "project"))
        let relative = try requireString(args, "path")
        let recursive = try optionalBool(args, "recursive") ?? false
        let allowConfig = try optionalBool(args, "allow_config") ?? false

        let url = try resolvePath(relative, in: project, allowProjectRoot: false)
        try guardConfig(relative: relative, allowed: allowConfig)

        let fm = FileManager.default
        var isDirectory: ObjCBool = false
        guard fm.fileExists(atPath: url.path, isDirectory: &isDirectory) else {
            throw NXToolError("not found: \(relative)")
        }
        if isDirectory.boolValue && !recursive {
            throw NXToolError("is a directory; pass recursive: true to delete: \(relative)")
        }

        do {
            try fm.removeItem(at: url)
        } catch {
            throw NXToolError("delete failed: \(error.localizedDescription)")
        }
        return ["deleted": relative, "type": isDirectory.boolValue ? "directory" : "file"]
    }

    // MARK: nx_search

    private func toolSearch(_ args: [String: Any]) throws -> [String: Any] {
        let project = try projectURL(try requireString(args, "project"))
        let query = try requireString(args, "query")
        let relative = try optionalString(args, "path") ?? ""
        let extensionFilter = (try optionalString(args, "extension"))?.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        let caseSensitive = try optionalBool(args, "case_sensitive") ?? false
        let requestedMax = try optionalInt(args, "max_results") ?? 100
        let maxResults = min(max(requestedMax, 1), 1000)

        let searchRoot = try resolvePath(relative, in: project, allowProjectRoot: true)
        let fm = FileManager.default
        guard fm.fileExists(atPath: searchRoot.path) else {
            throw NXToolError("path not found: \(relative.isEmpty ? "/" : relative)")
        }

        let options: String.CompareOptions = caseSensitive ? [] : [.caseInsensitive]
        let projectPrefix = project.resolvingSymlinksInPath().path + "/"
        let maxFileBytes = 1024 * 1024

        var matches: [[String: Any]] = []
        var filesScanned = 0
        var truncated = false

        guard let enumerator = fm.enumerator(at: searchRoot, includingPropertiesForKeys: [.isDirectoryKey, .fileSizeKey], options: []) else {
            throw NXToolError("could not enumerate directory")
        }

        for case let url as URL in enumerator {
            if matches.count >= maxResults {
                truncated = true
                break
            }
            let values = try? url.resourceValues(forKeys: [.isDirectoryKey, .fileSizeKey])
            guard let values, !(values.isDirectory ?? true) else { continue }

            if let extensionFilter, !extensionFilter.isEmpty {
                let fileExtension = url.pathExtension.lowercased()
                guard fileExtension == extensionFilter || (fileExtension.isEmpty && url.lastPathComponent.lowercased().hasSuffix("." + extensionFilter)) else {
                    continue
                }
            }

            guard let size = values.fileSize, size <= maxFileBytes else { continue }
            guard let data = try? Data(contentsOf: url), !data.isEmpty,
                  let text = String(data: data, encoding: .utf8) else {
                continue
            }
            filesScanned += 1

            let relativePath = relativePathString(of: url, projectPath: projectPrefix)
            let lines = text.components(separatedBy: "\n")
            for (index, line) in lines.enumerated() {
                if matches.count >= maxResults {
                    truncated = true
                    break
                }
                guard line.range(of: query, options: options) != nil else { continue }
                var excerpt = line.trimmingCharacters(in: .whitespacesAndNewlines)
                if excerpt.count > 300 {
                    excerpt = String(excerpt.prefix(300)) + "…"
                }
                matches.append([
                    "path": relativePath,
                    "line": index + 1,
                    "text": excerpt
                ])
            }
        }

        return [
            "query": query,
            "matches": matches,
            "count": matches.count,
            "files_scanned": filesScanned,
            "truncated": truncated
        ]
    }

    // MARK: - Argument helpers

    private func requireString(_ args: [String: Any], _ key: String, allowEmpty: Bool = false) throws -> String {
        guard let value = args[key] as? String, allowEmpty || !value.isEmpty else {
            throw NXToolError("missing or empty argument: \(key)")
        }
        return value
    }

    private func optionalString(_ args: [String: Any], _ key: String) throws -> String? {
        if let value = args[key] {
            guard value is NSNull || value is String else {
                throw NXToolError("argument \(key) must be a string")
            }
            return value as? String
        }
        return nil
    }

    private func optionalBool(_ args: [String: Any], _ key: String) throws -> Bool? {
        guard let value = args[key] else { return nil }
        if value is NSNull { return nil }
        guard let boolean = value as? Bool else {
            throw NXToolError("argument \(key) must be a boolean")
        }
        return boolean
    }

    private func optionalInt(_ args: [String: Any], _ key: String) throws -> Int? {
        guard let value = args[key] else { return nil }
        if value is NSNull { return nil }
        guard let number = value as? NSNumber else {
            throw NXToolError("argument \(key) must be an integer")
        }
        return number.intValue
    }

    // MARK: - Path sandbox

    /// `<Documents>/Projects` — mirrors `NXBootstrap.projectsURL`.
    private func projectsRootURL() throws -> URL {
        guard let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
            throw NXToolError("documents directory unavailable")
        }
        return documents.appendingPathComponent("Projects", isDirectory: true)
    }

    /// Validates the project id (single path component, existing directory
    /// directly under the projects root).
    private func projectURL(_ id: String) throws -> URL {
        guard !id.isEmpty, !id.contains("/"), !id.contains(":"), id != ".", id != ".." else {
            throw NXToolError("invalid project id: \(id)")
        }
        let root = try projectsRootURL()
        let project = root.appendingPathComponent(id, isDirectory: true)
        let standardized = project.standardizedFileURL

        let rootPrefix = root.standardizedFileURL.path
        guard standardized.path.hasPrefix(rootPrefix + "/") else {
            throw NXToolError("invalid project id: \(id)")
        }

        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: standardized.path, isDirectory: &isDirectory),
              isDirectory.boolValue
        else {
            throw NXToolError("unknown project: \(id)")
        }
        return standardized
    }

    /// Resolves a client-supplied relative path inside the project. Rejects
    /// `..`, absolute paths, and anything that escapes after standardization
    /// or symlink resolution.
    private func resolvePath(_ relative: String, in project: URL, allowProjectRoot: Bool) throws -> URL {
        var trimmed = relative
        while trimmed.hasPrefix("/") {
            trimmed = String(trimmed.dropFirst())
        }
        let components = trimmed.split(separator: "/").map(String.init)
        guard !components.contains("..") else {
            throw NXToolError("path escapes the project: \(relative)")
        }

        let resolved = trimmed.isEmpty
            ? project
            : project.appendingPathComponent(trimmed).standardizedFileURL

        let projectStandard = project.standardizedFileURL.path
        let projectResolved = project.resolvingSymlinksInPath().path
        let resolvedStandard = resolved.standardizedFileURL.path
        let resolvedSymlink = resolved.resolvingSymlinksInPath().path

        let standardOK = resolvedStandard == projectStandard
            ? allowProjectRoot
            : resolvedStandard.hasPrefix(projectStandard + "/")
        let symlinkOK = resolvedSymlink == projectResolved
            ? allowProjectRoot
            : resolvedSymlink.hasPrefix(projectResolved + "/")

        guard standardOK, symlinkOK else {
            throw NXToolError("path escapes the project: \(relative)")
        }
        return resolved
    }

    /// `Config/` holds build configuration; mutation requires explicit opt-in.
    private func guardConfig(relative: String, allowed: Bool) throws {
        guard !allowed else { return }
        let trimmed = relative.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        if trimmed == "Config" || trimmed.hasPrefix("Config/") {
            throw NXToolError("refusing to modify Config/; pass allow_config: true to override")
        }
    }
}

// MARK: - Minimal HTTP parsing

/// One parsed HTTP/1.x request head plus its body, read from a buffer.
struct NXHTTPServerRequest {

    let method: String
    let path: String
    let headers: [String: String]
    let body: Data

    /// Content-Length declared by the head, when the head is complete.
    static func declaredContentLength(in data: Data) -> Int? {
        guard let separator = data.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        guard let head = String(data: data.subdata(in: data.startIndex..<separator.lowerBound), encoding: .utf8) else {
            return nil
        }
        for line in head.components(separatedBy: "\r\n").dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = String(line[line.startIndex..<colon]).trimmingCharacters(in: .whitespaces).lowercased()
            if name == "content-length" {
                let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
                return Int(value)
            }
        }
        return nil
    }

    /// Returns a request once the buffer contains a full head and the body
    /// named by `Content-Length`; nil means "keep reading".
    init?(data: Data) {
        guard let separatorRange = data.range(of: Data("\r\n\r\n".utf8)) else {
            return nil
        }

        guard let headText = String(data: data.subdata(in: data.startIndex..<separatorRange.lowerBound), encoding: .utf8) else {
            return nil
        }

        var headLines = headText.components(separatedBy: "\r\n")
        guard !headLines.isEmpty else { return nil }
        let requestLine = headLines.removeFirst().components(separatedBy: " ")
        guard requestLine.count >= 2 else { return nil }

        self.method = requestLine[0]
        self.path = requestLine[1]

        var headers: [String: String] = [:]
        for line in headLines where !line.isEmpty {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = String(line[line.startIndex..<colon]).trimmingCharacters(in: .whitespaces).lowercased()
            let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            headers[name] = value
        }
        self.headers = headers

        let bodyStart = separatorRange.upperBound
        let contentLength = Int(headers["content-length"] ?? "0") ?? 0
        guard contentLength >= 0, contentLength <= NXMCPServer.maxBodyBytes else { return nil }

        guard data.distance(from: bodyStart, to: data.endIndex) >= contentLength else {
            return nil
        }

        if contentLength > 0 {
            let end = data.index(bodyStart, offsetBy: contentLength)
            self.body = data.subdata(in: bodyStart..<end)
        } else {
            self.body = Data()
        }
    }
}

/// One HTTP/1.x response, rendered to bytes once.
struct NXHTTPServerResponse {

    let status: Int
    let contentType: String
    let body: Data
    var extraHeaders: [String: String] = [:]

    private static let reasonPhrases: [Int: String] = [
        200: "OK",
        202: "Accepted",
        401: "Unauthorized",
        404: "Not Found",
        405: "Method Not Allowed",
        413: "Payload Too Large",
        500: "Internal Server Error"
    ]

    var render: Data {
        let reason = NXHTTPServerResponse.reasonPhrases[status] ?? "Unknown"
        var head = "HTTP/1.1 \(status) \(reason)\r\n" +
            "Content-Type: \(contentType)\r\n"
        for (name, value) in extraHeaders.sorted(by: { $0.key < $1.key }) {
            head += "\(name): \(value)\r\n"
        }
        head += "Content-Length: \(body.count)\r\n" +
            "Connection: close\r\n" +
            "\r\n"
        var data = Data(head.utf8)
        data.append(body)
        return data
    }
}

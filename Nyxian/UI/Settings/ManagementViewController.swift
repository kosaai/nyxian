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

import UIKit
import Security

/// Textual contract shared with NXMCPServer (app target). The two targets
/// compile independently — no imports possible — so the strings are
/// duplicated verbatim. Keep in sync with the copy in NXMCPServer.swift.
private enum NXMCPContract {
    static let enabledKey = "NXMCPServer.Enabled"
    static let runningKey = "NXMCPServer.Running"
    static let enabledChangedNotification = "NXMCPServerEnabledChanged"
    static let stateChangedNotification = "NXMCPServerStateChanged"
    static let keychainService = "app.nyxian.mcp-server"
    static let keychainAccount = "auth-token"
    static let port = 8377
}

class NXManagementUISingleFlight {
    private static let slot = DispatchSemaphore(value: 1)
    private static let queue = DispatchQueue(label: "org.emexlabs.nyxian.mgmt.singleflight", qos: .userInitiated)
    
    @discardableResult static func run(_ body: @escaping () -> Void) -> Bool {
        guard slot.wait(timeout: .now()) == .success else { return false }
        queue.async {
            defer { self.slot.signal() }
            body()
        }
        return true
    }
}

class ManagementViewController: NXUITableViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        title = "Management"
        view.backgroundColor = .systemBackground
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(mcpServerStateChanged),
            name: Notification.Name(NXMCPContract.stateChangedNotification),
            object: nil
        )
    }
    
    override func numberOfSections(in tableView: UITableView) -> Int {
        return 5
    }
    
    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        switch(section) {
            case 0:
                return 1
            case 1:
                return 1
            case 2:
                return 2
            case 3:
                return 6
            default:
                return 4
        }
    }
    
    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let tableViewCell: UITableViewCell = UITableViewCell()
        
        switch(indexPath.section) {
            case 0:
                tableViewCell.textLabel?.text = "Browse Virtual File System"
                tableViewCell.accessoryType = .disclosureIndicator
            case 1:
                tableViewCell.textLabel?.text = "Installed Root Certificate Authorities"
                tableViewCell.accessoryType = .disclosureIndicator
            case 2:
                if indexPath.row == 0 {
                    tableViewCell.textLabel?.text = "Installed Applications"
                    tableViewCell.accessoryType = .disclosureIndicator
                } else if indexPath.row == 1 {
                    tableViewCell.textLabel?.text = "Installed KEXTs"
                    tableViewCell.accessoryType = .disclosureIndicator
                }
            case 3:
                if indexPath.row == 0 {
                    tableViewCell.textLabel?.text = "Clear IconCache"
                } else if indexPath.row == 1 {
                    tableViewCell.textLabel?.text = "Userspace Reboot"
                } else if indexPath.row == 2 {
                    tableViewCell.textLabel?.text = "Reload Daemons"
                } else if indexPath.row == 3 {
                    tableViewCell.textLabel?.text = "Clear Application Caches"
                    tableViewCell.textLabel?.textColor = .systemRed
                } else if indexPath.row == 4 {
                    tableViewCell.textLabel?.text = "Restore Virtual Environment"
                    tableViewCell.textLabel?.textColor = .systemRed
                } else if indexPath.row == 5 {
                    tableViewCell.textLabel?.text = "Restore Everything"
                    tableViewCell.textLabel?.textColor = .systemRed
                }
            case 4:
                if indexPath.row == 0 {
                    let enabled = UserDefaults.standard.object(forKey: NXMCPContract.enabledKey) as? Bool ?? true
                    tableViewCell.textLabel?.text = "MCP Server"
                    let toggle = UISwitch()
                    toggle.isOn = enabled
                    toggle.addTarget(self, action: #selector(mcpServerToggleChanged(_:)), for: .valueChanged)
                    tableViewCell.accessoryView = toggle
                } else if indexPath.row == 1 {
                    let running = UserDefaults.standard.bool(forKey: NXMCPContract.runningKey)
                    tableViewCell.textLabel?.text = running ? "Status: Running" : "Status: Stopped"
                    tableViewCell.textLabel?.textColor = running ? .systemGreen : .secondaryLabel
                    tableViewCell.selectionStyle = .none
                } else if indexPath.row == 2 {
                    tableViewCell.textLabel?.text = "Port: \(NXMCPContract.port)"
                    tableViewCell.selectionStyle = .none
                } else if let token = mcpServerToken(), !token.isEmpty {
                    let prefix = String(token.prefix(8))
                    tableViewCell.textLabel?.text = "Token: \(prefix)… (tap to copy)"
                } else {
                    tableViewCell.textLabel?.text = "Token: unavailable"
                    tableViewCell.textLabel?.textColor = .secondaryLabel
                    tableViewCell.selectionStyle = .none
                }
        }
        
        return tableViewCell
    }
    
    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        switch(indexPath.section) {
        case 0:
            navigationController?.pushViewController(FileListViewController(isSublink: true, path: NXBootstrap.shared().rootfsURL.path), animated: true)
        case 1:
            print("pressed on list RootCAs")
        case 2:
            if indexPath.row == 0 {
                navigationController?.pushViewController(ApplicationManagementViewController(style: .insetGrouped), animated: true)
            } else {
                navigationController?.pushViewController(KEXTManagementViewController(style: .insetGrouped), animated: true)
            }
        case 3:
            if indexPath.row == 0 {
                ProjectTableCell.iconCache.removeAllObjects()
            } else if indexPath.row == 1 {
                NXManagementUISingleFlight.run {
                    PEUserspaceManager.shared().rebootUserspace()
                }
            } else if indexPath.row == 2 {
                NXManagementUISingleFlight.run {
                    PEUserspaceManager.shared().reloadDaemons()
                }
            } else if indexPath.row == 3 {
                let alert = UIAlertController(
                    title: "Clear Application Caches",
                    message: "All application caches will be wiped, this can have consequences, but it will result in less data being in use. (Some people like that for performance reasons)",
                    preferredStyle: .alert
                )
                
                alert.addAction(UIAlertAction(title: "Proceed", style: .destructive) { [weak self] _ in
                    DispatchQueue.main.async {
                        let alert = UIAlertController(title: nil, message: "Clearing Application Caches", preferredStyle: .alert)
                        
                        let activityIndicator = UIActivityIndicatorView(style: .medium)
                        activityIndicator.translatesAutoresizingMaskIntoConstraints = false
                        activityIndicator.startAnimating()
                        
                        alert.view.addSubview(activityIndicator)
                        
                        NSLayoutConstraint.activate([
                            activityIndicator.centerYAnchor.constraint(equalTo: alert.view.centerYAnchor),
                            activityIndicator.trailingAnchor.constraint(equalTo: alert.view.trailingAnchor, constant: -20)
                        ])
                        
                        guard let self = self else {
                            return
                        }
                        self.present(alert, animated: true) { [weak self] in
                            guard let self = self else {
                                return
                            }
                            DispatchQueue.global().async { [weak self] in
                                guard let self = self else {
                                    return
                                }
                                let success = PEUserspaceManager.shared().clearApplicationCaches()
                                DispatchQueue.main.async { [weak self] in
                                    guard let self = self else {
                                        return
                                    }
                                    alert.dismiss(animated: true)
                                    if !success {
                                        let alert = UIAlertController(
                                            title: "Error",
                                            message: "Clearing Application Caches failed",
                                            preferredStyle: .alert
                                        )
                                        
                                        alert.addAction(UIAlertAction(title: "Close", style: .cancel))
                                        
                                        self.present(alert, animated: true)
                                    }
                                }
                            }
                        }
                    }
                })
                
                alert.addAction(UIAlertAction(title: "Keep Caches", style: .cancel))
                
                self.present(alert, animated: true)
            } else if indexPath.row == 4 {
                let alert = UIAlertController(
                    title: "Restore Virtual Environment",
                    message: "All apps, kexts, binaries and data containers in the virtual environment will be wiped.",
                    preferredStyle: .alert
                )
                
                alert.addAction(UIAlertAction(title: "Proceed", style: .destructive) { [weak self] _ in
                    DispatchQueue.main.async {
                        let alert = UIAlertController(title: nil, message: "Restoring", preferredStyle: .alert)
                        
                        let activityIndicator = UIActivityIndicatorView(style: .medium)
                        activityIndicator.translatesAutoresizingMaskIntoConstraints = false
                        activityIndicator.startAnimating()
                        
                        alert.view.addSubview(activityIndicator)
                        
                        NSLayoutConstraint.activate([
                            activityIndicator.centerYAnchor.constraint(equalTo: alert.view.centerYAnchor),
                            activityIndicator.trailingAnchor.constraint(equalTo: alert.view.trailingAnchor, constant: -20)
                        ])
                        
                        guard let self = self else {
                            return
                        }
                        self.present(alert, animated: true) { [weak self] in
                            guard let self = self else {
                                return
                            }
                            DispatchQueue.global().async { [weak self] in
                                guard let self = self else {
                                    return
                                }
                                let success = PEUserspaceManager.shared().restore()
                                DispatchQueue.main.async { [weak self] in
                                    guard let self = self else {
                                        return
                                    }
                                    alert.dismiss(animated: true)
                                    if !success {
                                        let alert = UIAlertController(
                                            title: "Error",
                                            message: "Restore failed",
                                            preferredStyle: .alert
                                        )
                                        
                                        alert.addAction(UIAlertAction(title: "Close", style: .cancel))
                                        
                                        self.present(alert, animated: true)
                                    }
                                }
                            }
                        }
                    }
                })
                
                alert.addAction(UIAlertAction(title: "Keep Data", style: .cancel))
                
                self.present(alert, animated: true)
            } else if indexPath.row == 5 {
                let alert = UIAlertController(
                    title: "Restore Everything",
                    message: "All projects, configurations, kexts, apps, binaries and data containers in the virtual environment will be wiped.",
                    preferredStyle: .alert
                )
                
                alert.addAction(UIAlertAction(title: "Proceed", style: .destructive) { [weak self] _ in
                    DispatchQueue.main.async {
                        let alert = UIAlertController(title: nil, message: "Restoring", preferredStyle: .alert)
                        
                        let activityIndicator = UIActivityIndicatorView(style: .medium)
                        activityIndicator.translatesAutoresizingMaskIntoConstraints = false
                        activityIndicator.startAnimating()
                        
                        alert.view.addSubview(activityIndicator)
                        
                        NSLayoutConstraint.activate([
                            activityIndicator.centerYAnchor.constraint(equalTo: alert.view.centerYAnchor),
                            activityIndicator.trailingAnchor.constraint(equalTo: alert.view.trailingAnchor, constant: -20)
                        ])
                        
                        guard let self = self else {
                            return
                        }
                        self.present(alert, animated: true) { [weak self] in
                            guard let self = self else {
                                return
                            }
                            DispatchQueue.global().async { [weak self] in
                                guard let self = self else {
                                    return
                                }
                                let success = PEUserspaceManager.shared().restoreEverything()
                                DispatchQueue.main.async { [weak self] in
                                    guard let self = self else {
                                        return
                                    }
                                    alert.dismiss(animated: true)
                                    if !success {
                                        let alert = UIAlertController(
                                            title: "Error",
                                            message: "Restore failed",
                                            preferredStyle: .alert
                                        )
                                        
                                        alert.addAction(UIAlertAction(title: "Close", style: .cancel))
                                        
                                        self.present(alert, animated: true)
                                    }
                                }
                            }
                        }
                    }
                })
                
                alert.addAction(UIAlertAction(title: "Keep Data", style: .cancel))
                
                self.present(alert, animated: true)
            }
        case 4:
            if indexPath.row == 3, let token = mcpServerToken(), !token.isEmpty {
                UIPasteboard.general.string = token
                UINotificationFeedbackGenerator().notificationOccurred(.success)
                if let cell = tableView.cellForRow(at: indexPath) {
                    cell.accessoryType = .checkmark
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
                        cell.accessoryType = .disclosureIndicator
                    }
                }
            }
        }
        tableView.deselectRow(at: indexPath, animated: true)
    }
    
    // MARK: - MCP server settings (section 4)
    
    /// Settings toggle: persists the user's choice and notifies the server,
    /// which starts or stops itself on its own queue.
    @objc private func mcpServerToggleChanged(_ sender: UISwitch) {
        UserDefaults.standard.set(sender.isOn, forKey: NXMCPContract.enabledKey)
        NotificationCenter.default.post(
            name: Notification.Name(NXMCPContract.enabledChangedNotification),
            object: nil
        )
    }
    
    /// Server posts this on main whenever the listener's state flips.
    @objc private func mcpServerStateChanged() {
        if tableView.numberOfSections > 4 {
            tableView.reloadSections(IndexSet(integer: 4), with: .none)
        }
    }
    
    /// Reads the Bearer token straight from the Keychain using the shared
    /// contract — no reference to NXMCPServer (different target).
    private func mcpServerToken() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: NXMCPContract.keychainService,
            kSecAttrAccount as String: NXMCPContract.keychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }
}

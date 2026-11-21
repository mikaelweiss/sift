import SwiftUI

struct SettingsSheet: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    @State private var draftSettings = AppSettings()
    @State private var imapPasswordInput = ""
    @State private var aiAPIKeyInput = ""
    @State private var newCategoryName = ""
    @State private var newCategoryDescription = ""
    @State private var newAllowlistPattern = ""

    @State private var statusBanner: String?
    @State private var isSaving = false
    @State private var isTestingIMAP = false
    @State private var isTestingAI = false

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Settings")
                    .font(.title2.bold())
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)

            Divider()

            TabView {
                filteringTab
                    .tabItem { Label("Categories & Action", systemImage: "line.3.horizontal.decrease.circle") }
                allowlistTab
                    .tabItem { Label("Allowlist", systemImage: "checkmark.shield") }
                credentialsTab
                    .tabItem { Label("iCloud & AI", systemImage: "key") }
                serverTab
                    .tabItem { Label("Server & Macs", systemImage: "server.rack") }
            }
            .padding(16)

            if let statusBanner {
                Divider()
                HStack {
                    Text(statusBanner)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 8)
            }
        }
        .frame(width: 680, height: 540)
        .onAppear {
            draftSettings = appState.settings
        }
    }

    private var filteringTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                GroupBox("Spam Action & Thresholds") {
                    VStack(alignment: .leading, spacing: 10) {
                        Picker("When spam is detected", selection: $draftSettings.spamAction) {
                            Text("Move to Trash").tag("trash")
                            Text("Delete Permanently").tag("delete")
                        }
                        .pickerStyle(.segmented)

                        HStack {
                            Text("Trash confidence threshold: \(Int(draftSettings.trashThreshold * 100))%")
                                .frame(width: 240, alignment: .leading)
                            Slider(value: $draftSettings.trashThreshold, in: 0.50...0.99, step: 0.01)
                        }

                        HStack {
                            Text("Permanent delete threshold: \(Int(draftSettings.deleteThreshold * 100))%")
                                .frame(width: 240, alignment: .leading)
                            Slider(value: $draftSettings.deleteThreshold, in: 0.70...0.99, step: 0.01)
                        }

                        HStack {
                            Spacer()
                            Button("Save Action Settings") {
                                Task { await saveSettings() }
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(isSaving)
                        }
                    }
                    .padding(8)
                }

                GroupBox("Blocked Categories") {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(appState.categories) { cat in
                            HStack {
                                Toggle(isOn: Binding(
                                    get: { cat.enabled },
                                    set: { newValue in
                                        var updated = cat
                                        updated.enabled = newValue
                                        Task { await updateCategory(updated) }
                                    }
                                )) {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(cat.name).font(.body.weight(.medium))
                                        Text(cat.description).font(.caption).foregroundStyle(.secondary)
                                    }
                                }
                                Spacer()
                                if !cat.builtin {
                                    Button(role: .destructive) {
                                        Task { await deleteCategory(cat.id) }
                                    } label: {
                                        Image(systemName: "trash")
                                    }
                                    .buttonStyle(.borderless)
                                }
                            }
                            Divider()
                        }

                        HStack {
                            TextField("Custom category name", text: $newCategoryName)
                                .textFieldStyle(.roundedBorder)
                            TextField("Description", text: $newCategoryDescription)
                                .textFieldStyle(.roundedBorder)
                            Button("Add") {
                                Task { await addCategory() }
                            }
                            .disabled(newCategoryName.trimmingCharacters(in: .whitespaces).isEmpty)
                        }
                    }
                    .padding(8)
                }
            }
            .padding(4)
        }
    }

    private var allowlistTab: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Senders and domains listed here bypass Jev and are never moved or deleted.")
                .font(.callout)
                .foregroundStyle(.secondary)

            HStack {
                TextField("Email address or domain (e.g. bank.com or mom@icloud.com)", text: $newAllowlistPattern)
                    .textFieldStyle(.roundedBorder)
                Button("Add") {
                    Task { await addAllowlist() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(newAllowlistPattern.trimmingCharacters(in: .whitespaces).isEmpty)
            }

            List {
                ForEach(appState.allowlist) { entry in
                    HStack {
                        Image(systemName: entry.kind == "email" ? "envelope" : "globe")
                            .foregroundStyle(.secondary)
                        Text(entry.pattern)
                        Spacer()
                        Text(entry.kind)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Button(role: .destructive) {
                            Task { await removeAllowlist(entry.id) }
                        } label: {
                            Image(systemName: "trash")
                        }
                        .buttonStyle(.borderless)
                    }
                }
            }
            .listStyle(.bordered)
        }
        .padding(4)
    }

    private var credentialsTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                GroupBox("iCloud Mail (IMAP)") {
                    VStack(alignment: .leading, spacing: 10) {
                        TextField("iCloud Email", text: $draftSettings.imapUsername)
                            .textFieldStyle(.roundedBorder)
                        SecureField(appState.settings.hasIMAPPassword == true ? "App-Specific Password (saved, leave blank to keep)" : "App-Specific Password", text: $imapPasswordInput)
                            .textFieldStyle(.roundedBorder)
                        HStack {
                            Button(isTestingIMAP ? "Testing..." : "Test IMAP Connection") {
                                Task { await testIMAP() }
                            }
                            .disabled(isTestingIMAP)
                            Spacer()
                            Button("Save Credentials") {
                                Task { await saveSettings() }
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(isSaving)
                        }
                    }
                    .padding(8)
                }

                GroupBox("TypeSafe / OpenRouter API") {
                    VStack(alignment: .leading, spacing: 10) {
                        Picker("Provider", selection: $draftSettings.aiProvider) {
                            Text("TypeSafe").tag("typesafe")
                            Text("OpenRouter").tag("openrouter")
                        }
                        .pickerStyle(.segmented)
                        SecureField(appState.settings.hasAIAPIKey == true ? "API Key (saved, leave blank to keep)" : "API Key", text: $aiAPIKeyInput)
                            .textFieldStyle(.roundedBorder)
                        TextField("Model", text: $draftSettings.aiModel)
                            .textFieldStyle(.roundedBorder)
                        HStack {
                            Button(isTestingAI ? "Testing..." : "Test AI Key") {
                                Task { await testAI() }
                            }
                            .disabled(isTestingAI)
                            Spacer()
                            Button("Save Credentials") {
                                Task { await saveSettings() }
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(isSaving)
                        }
                    }
                    .padding(8)
                }
            }
            .padding(4)
        }
    }

    private var serverTab: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let conn = appState.connection {
                GroupBox("Connected Server") {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Host: \(conn.host):\(conn.port) (\(conn.isLocal ? "This Mac" : "Remote SSH"))")
                            .font(.callout)
                        if let health = appState.health {
                            Text("Version: v\(health.version) (\(health.os)/\(health.arch)) · Bundled: v\(appState.bundledServerVersion)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Text("TLS SHA-256: \(conn.tlsFingerprint.prefix(24))...")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                        HStack {
                            Button(appState.isUpdatingServer ? "Updating..." : "Reinstall / Update Server Binary") {
                                Task { await appState.updateServerBinary() }
                            }
                            .disabled(appState.isUpdatingServer)
                            Spacer()
                            Button("Sign Out This Mac", role: .destructive) {
                                Task {
                                    await appState.signOut()
                                    dismiss()
                                }
                            }
                        }
                        .padding(.top, 4)
                    }
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }

            Text("Paired Macs")
                .font(.headline)

            List {
                ForEach(appState.devices) { device in
                    HStack {
                        Image(systemName: "laptopcomputer")
                        VStack(alignment: .leading) {
                            HStack(spacing: 6) {
                                Text(device.name).font(.body.weight(.medium))
                                if device.id == appState.connection?.deviceID {
                                    Text("This Mac")
                                        .font(.caption2)
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(Color.accentColor.opacity(0.15), in: Capsule())
                                }
                            }
                            Text("Last seen: \(device.lastSeenAt)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        if device.id != appState.connection?.deviceID {
                            Button("Revoke", role: .destructive) {
                                Task { await revokeDevice(device.id) }
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                        }
                    }
                }
            }
            .listStyle(.bordered)
        }
        .padding(4)
    }

    private func saveSettings() async {
        guard let client = appState.apiClient else { return }
        isSaving = true
        defer { isSaving = false }
        var payload = draftSettings
        if !imapPasswordInput.isEmpty { payload.imapPassword = imapPasswordInput }
        if !aiAPIKeyInput.isEmpty { payload.aiAPIKey = aiAPIKeyInput }
        do {
            let updated = try await client.updateSettings(payload)
            appState.settings = updated
            draftSettings = updated
            imapPasswordInput = ""
            aiAPIKeyInput = ""
            statusBanner = "Settings saved."
        } catch {
            statusBanner = "Save failed: \(error.localizedDescription)"
        }
    }

    private func testIMAP() async {
        guard let client = appState.apiClient else { return }
        isTestingIMAP = true
        defer { isTestingIMAP = false }
        do {
            let res = try await client.validateIMAP(
                host: draftSettings.imapHost,
                port: draftSettings.imapPort,
                username: draftSettings.imapUsername,
                password: imapPasswordInput
            )
            statusBanner = res.ok ? "iCloud IMAP connection succeeded." : "IMAP test failed: \(res.error)"
        } catch {
            statusBanner = "IMAP test failed: \(error.localizedDescription)"
        }
    }

    private func testAI() async {
        guard let client = appState.apiClient else { return }
        isTestingAI = true
        defer { isTestingAI = false }
        do {
            let res = try await client.validateAI(
                provider: draftSettings.aiProvider,
                apiKey: aiAPIKeyInput,
                model: draftSettings.aiModel
            )
            statusBanner = res.ok ? "Jev API key verified." : "AI test failed: \(res.error)"
        } catch {
            statusBanner = "AI test failed: \(error.localizedDescription)"
        }
    }

    private func updateCategory(_ cat: Category) async {
        guard let client = appState.apiClient else { return }
        do {
            _ = try await client.updateCategory(cat)
            appState.categories = try await client.listCategories()
            statusBanner = "Updated category \(cat.name)."
        } catch {
            statusBanner = "Failed: \(error.localizedDescription)"
        }
    }

    private func addCategory() async {
        guard let client = appState.apiClient else { return }
        do {
            _ = try await client.createCategory(
                name: newCategoryName.trimmingCharacters(in: .whitespaces),
                description: newCategoryDescription.trimmingCharacters(in: .whitespaces),
                enabled: true,
                abuseEligible: false
            )
            newCategoryName = ""
            newCategoryDescription = ""
            appState.categories = try await client.listCategories()
            statusBanner = "Added custom category."
        } catch {
            statusBanner = "Failed: \(error.localizedDescription)"
        }
    }

    private func deleteCategory(_ id: String) async {
        guard let client = appState.apiClient else { return }
        do {
            try await client.deleteCategory(id: id)
            appState.categories = try await client.listCategories()
            statusBanner = "Deleted category."
        } catch {
            statusBanner = "Failed: \(error.localizedDescription)"
        }
    }

    private func addAllowlist() async {
        guard let client = appState.apiClient else { return }
        let pattern = newAllowlistPattern.trimmingCharacters(in: .whitespaces)
        let kind = pattern.contains("@") ? "email" : "domain"
        do {
            _ = try await client.addAllowlist(pattern: pattern, kind: kind)
            newAllowlistPattern = ""
            appState.allowlist = try await client.listAllowlist()
            statusBanner = "Added \(pattern) to allowlist."
        } catch {
            statusBanner = "Failed: \(error.localizedDescription)"
        }
    }

    private func removeAllowlist(_ id: Int64) async {
        guard let client = appState.apiClient else { return }
        do {
            try await client.deleteAllowlist(id: id)
            appState.allowlist = try await client.listAllowlist()
            statusBanner = "Removed allowlist entry."
        } catch {
            statusBanner = "Failed: \(error.localizedDescription)"
        }
    }

    private func revokeDevice(_ id: String) async {
        guard let client = appState.apiClient else { return }
        do {
            try await client.revokeDevice(id: id)
            appState.devices = try await client.listDevices()
            statusBanner = "Revoked device."
        } catch {
            statusBanner = "Failed: \(error.localizedDescription)"
        }
    }
}

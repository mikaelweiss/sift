import SwiftUI

struct AbuseReportingSetupView: View {
    @Environment(AppState.self) private var appState
    @State private var draft = AppSettings()
    @State private var smtpPasswordInput = ""
    @State private var testRecipient = ""
    @State private var statusMessage: String?
    @State private var isSaving = false
    @State private var isSendingTest = false

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.title3)
                        .foregroundStyle(.yellow)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Deterministic Abuse Reporting")
                            .font(.headline)
                        Text("Look up hosting and registrar abuse@ contacts via RDAP/WHOIS for high-confidence spam and report with redacted headers.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Toggle("Enable", isOn: $draft.abuseEnabled)
                        .labelsHidden()
                }

                if draft.abuseEnabled {
                    Divider()

                    Toggle("Require manual approval before sending (review via top-right yellow icon)", isOn: $draft.abuseManualApproval)

                    HStack {
                        Text("Minimum confidence: \(Int(draft.abuseMinConfidence * 100))%")
                            .frame(width: 210, alignment: .leading)
                        Slider(value: $draft.abuseMinConfidence, in: 0.85...0.99, step: 0.01)
                    }

                    Stepper("Repeat-domain cooldown: \(draft.abuseCooldownDays) days", value: $draft.abuseCooldownDays, in: 1...30)

                    VStack(alignment: .leading, spacing: 6) {
                        Text("Qualifying Categories")
                            .font(.subheadline.weight(.medium))
                        ForEach(appState.categories) { cat in
                            Toggle(cat.name, isOn: Binding(
                                get: { cat.abuseEligible },
                                set: { newVal in
                                    var updated = cat
                                    updated.abuseEligible = newVal
                                    Task { await updateCategory(updated) }
                                }
                            ))
                            .font(.callout)
                        }
                    }

                    Divider()

                    VStack(alignment: .leading, spacing: 8) {
                        Text("Outbound Reporting Identity")
                            .font(.subheadline.weight(.medium))
                        Text("Use an iCloud Mail alias or custom SMTP account so your primary address stays private.")
                            .font(.caption)
                            .foregroundStyle(.secondary)

                        Picker("SMTP Mode", selection: $draft.abuseSMTPMode) {
                            Text("iCloud Mail Alias (smtp.mail.me.com)").tag("icloud_alias")
                            Text("Custom SMTP").tag("custom")
                        }
                        .pickerStyle(.segmented)

                        TextField("From Email / Alias", text: $draft.abuseFromEmail, prompt: Text(verbatim: "From Email / Alias (e.g. abuse-alias@icloud.com)"))
                            .textFieldStyle(.roundedBorder)

                        if draft.abuseSMTPMode == "custom" {
                            HStack {
                                TextField("SMTP Host", text: $draft.abuseSMTPHost)
                                    .textFieldStyle(.roundedBorder)
                                TextField("Port", value: $draft.abuseSMTPPort, format: .number)
                                    .textFieldStyle(.roundedBorder)
                                    .frame(width: 90)
                            }
                            TextField("SMTP Username", text: $draft.abuseSMTPUsername)
                                .textFieldStyle(.roundedBorder)
                            SecureField(appState.settings.hasAbuseSMTPPassword == true ? "SMTP Password (saved)" : "SMTP Password", text: $smtpPasswordInput)
                                .textFieldStyle(.roundedBorder)
                        }

                        HStack {
                            TextField("Test recipient email", text: $testRecipient)
                                .textFieldStyle(.roundedBorder)
                            Button(isSendingTest ? "Sending..." : "Send Test Email") {
                                Task { await sendTestEmail() }
                            }
                            .disabled(isSendingTest)
                        }
                    }
                }

                if let statusMessage {
                    Text(statusMessage)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                HStack {
                    Spacer()
                    Button(isSaving ? "Saving..." : "Save Abuse Reporting Settings") {
                        Task { await save() }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(isSaving)
                }
            }
            .padding(8)
        }
        .onAppear {
            draft = appState.settings
            testRecipient = appState.settings.abuseFromEmail
        }
    }

    private func save() async {
        guard let client = appState.apiClient else { return }
        isSaving = true
        defer { isSaving = false }
        var payload = draft
        if !smtpPasswordInput.isEmpty {
            payload.abuseSMTPPassword = smtpPasswordInput
        }
        do {
            let updated = try await client.updateSettings(payload)
            appState.settings = updated
            draft = updated
            smtpPasswordInput = ""
            statusMessage = "Abuse reporting settings saved."
        } catch {
            statusMessage = "Save failed: \(error.localizedDescription)"
        }
    }

    private func updateCategory(_ cat: Category) async {
        guard let client = appState.apiClient else { return }
        do {
            _ = try await client.updateCategory(cat)
            appState.categories = try await client.listCategories()
        } catch {
            statusMessage = "Category update failed: \(error.localizedDescription)"
        }
    }

    private func sendTestEmail() async {
        guard let client = appState.apiClient else { return }
        isSendingTest = true
        defer { isSendingTest = false }
        await save()
        do {
            let res = try await client.testAbuseSMTP(toEmail: testRecipient.trimmingCharacters(in: .whitespaces))
            statusMessage = res.ok ? "Test email sent successfully." : "SMTP test failed: \(res.error)"
        } catch {
            statusMessage = "SMTP test failed: \(error.localizedDescription)"
        }
    }
}

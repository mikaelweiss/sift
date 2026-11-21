import SwiftUI

struct HistoricalScanView: View {
    @Environment(AppState.self) private var appState
    @State private var dateRange = "30d"
    @State private var dryRun = true
    @State private var isSubmitting = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Historical Mail Scan")
                        .font(.headline)
                    Text("Scans INBOX, Junk, Archive, Trash, and custom iCloud folders.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Picker("Range", selection: $dateRange) {
                    Text("Last 30 Days").tag("30d")
                    Text("Last Year").tag("1y")
                    Text("All Mail").tag("all")
                }
                .labelsHidden()
                .frame(width: 130)

                Toggle("Dry Run", isOn: $dryRun)
                    .help("Preview matches without moving or deleting mail")

                actionButtons
            }

            if let errorMessage {
                Text(errorMessage)
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            if let job = appState.latestScan {
                Divider()
                scanStatusView(job)
            }
        }
        .padding(18)
        .background(Color.secondary.opacity(0.06), in: RoundedRectangle(cornerRadius: 12))
        .task(id: appState.latestScan?.status) {
            while appState.latestScan?.status == "running" {
                try? await Task.sleep(nanoseconds: 1_500_000_000)
                if Task.isCancelled { break }
                await appState.refreshLatestScan()
            }
        }
    }

    @ViewBuilder
    private var actionButtons: some View {
        if let job = appState.latestScan, job.status == "running" {
            Button("Pause") {
                Task { await pause(job.id) }
            }
            Button("Cancel", role: .destructive) {
                Task { await cancel(job.id) }
            }
        } else if let job = appState.latestScan, job.status == "paused" {
            Button("Resume") {
                Task { await resume(job.id) }
            }
            .buttonStyle(.borderedProminent)
            Button("Cancel", role: .destructive) {
                Task { await cancel(job.id) }
            }
        } else {
            Button(dryRun ? "Dry Run" : "Scan Mail") {
                Task { await startScan() }
            }
            .buttonStyle(.borderedProminent)
            .disabled(isSubmitting)
        }
    }

    private func scanStatusView(_ job: ScanJob) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                if job.status == "running" {
                    ProgressView().controlSize(.small)
                } else if job.status == "completed" {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                } else if job.status == "failed" {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                }
                Text(statusHeadline(job))
                    .font(.subheadline.weight(.medium))
                Spacer()
                Text("\(job.scannedMessages) / \(job.totalMessages) · \(job.spamFound) spam")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }

            if job.status == "running" && job.totalMessages == 0 {
                ProgressView()
                    .progressViewStyle(.linear)
            } else {
                ProgressView(value: job.progressFraction)
            }

            if job.status == "completed" && job.spamFound == 0 {
                Text("Checked \(job.scannedMessages) \(job.scannedMessages == 1 ? "email" : "emails") across your folders and found no spam.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if !job.errorMsg.isEmpty {
                Text("Error: \(job.errorMsg)")
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            if !job.samples.isEmpty {
                DisclosureGroup("Matched Emails (\(job.samples.count))") {
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(job.samples.prefix(20)) { sample in
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(sample.subject.isEmpty ? "(No subject)" : sample.subject)
                                        .font(.caption.weight(.medium))
                                        .lineLimit(1)
                                    Text("\(sample.mailbox ?? "INBOX") · \(sample.sender)")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                Text("\(sample.categoryID) · \(Int(sample.confidence * 100))%")
                                    .font(.caption2.monospacedDigit())
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(Color.orange.opacity(0.15), in: Capsule())
                            }
                        }
                    }
                    .padding(.top, 6)
                }
                .font(.caption)
            }
        }
    }

    private func statusHeadline(_ job: ScanJob) -> String {
        let mode = job.dryRun ? "Dry Run" : "Live"
        if job.status == "running", let folder = job.currentMailbox, !folder.isEmpty {
            return "Scanning \(folder) (\(mode), \(job.dateRange))"
        }
        return "\(job.status.capitalized) (\(mode), \(job.dateRange))"
    }

    private func startScan() async {
        guard let client = appState.apiClient else { return }
        errorMessage = nil
        isSubmitting = true
        defer { isSubmitting = false }
        do {
            appState.latestScan = try await client.startScan(dateRange: dateRange, dryRun: dryRun, ratePerSec: 5.0)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func pause(_ id: String) async {
        guard let client = appState.apiClient else { return }
        do {
            appState.latestScan = try await client.pauseScan(id: id)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func resume(_ id: String) async {
        guard let client = appState.apiClient else { return }
        do {
            appState.latestScan = try await client.resumeScan(id: id)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func cancel(_ id: String) async {
        guard let client = appState.apiClient else { return }
        do {
            appState.latestScan = try await client.cancelScan(id: id)
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

import SwiftUI

struct HistoricalScanView: View {
    @Environment(AppState.self) private var appState
    @State private var dateRange = "30d"
    @State private var dryRun = true
    @State private var ratePerSec = 5.0
    @State private var isSubmitting = false
    @State private var errorMessage: String?

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Image(systemName: "clock.arrow.circlepath")
                        .font(.title3)
                        .foregroundStyle(.blue)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Historical Inbox Scan")
                            .font(.headline)
                        Text("Scan existing emails on your server to clean old spam and backfill your Home stats chart.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                }

                if let errorMessage {
                    Text(errorMessage)
                        .font(.caption)
                        .foregroundStyle(.red)
                }

                HStack(spacing: 16) {
                    Picker("Date range", selection: $dateRange) {
                        Text("Last 30 Days").tag("30d")
                        Text("Last Year").tag("1y")
                        Text("All Mail").tag("all")
                    }
                    .frame(width: 240)

                    Toggle("Dry Run (preview only, do not move/delete)", isOn: $dryRun)
                }

                HStack {
                    Text("Rate limit: \(Int(ratePerSec)) emails/sec")
                        .font(.caption)
                        .frame(width: 160, alignment: .leading)
                    Slider(value: $ratePerSec, in: 1...15, step: 1)
                }

                if let job = appState.latestScan {
                    Divider()
                    scanStatusView(job)
                }

                HStack {
                    Spacer()
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
                        Button(dryRun ? "Start Dry Run Scan" : "Start Live Inbox Scan") {
                            Task { await startScan() }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(isSubmitting)
                    }
                }
            }
            .padding(8)
        }
    }

    private func scanStatusView(_ job: ScanJob) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Job Status: \(job.status.capitalized) (\(job.dryRun ? "Dry Run" : "Live"), \(job.dateRange))")
                    .font(.subheadline.weight(.medium))
                Spacer()
                Text("\(job.scannedMessages) / \(job.totalMessages) scanned · \(job.spamFound) spam")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }

            ProgressView(value: job.progressFraction)

            if !job.errorMsg.isEmpty {
                Text("Error: \(job.errorMsg)")
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            if !job.samples.isEmpty {
                DisclosureGroup("Matched Sample Emails (\(job.samples.count))") {
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(job.samples.prefix(15)) { sample in
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(sample.subject.isEmpty ? "(No subject)" : sample.subject)
                                        .font(.caption.weight(.medium))
                                        .lineLimit(1)
                                    Text(sample.sender)
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

    private func startScan() async {
        guard let client = appState.apiClient else { return }
        errorMessage = nil
        isSubmitting = true
        defer { isSubmitting = false }
        do {
            appState.latestScan = try await client.startScan(dateRange: dateRange, dryRun: dryRun, ratePerSec: ratePerSec)
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

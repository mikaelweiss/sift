import SwiftUI

struct HistoricalScanView: View {
    @Environment(AppState.self) private var appState
    @State private var dateRange = "30d"
    @State private var dryRun = true
    @State private var isSubmitting = false
    @State private var errorMessage: String?
    @State private var showMatches = false
    @State private var matches: [ScanMatch] = []
    @State private var matchesJobID: String?

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
            while appState.latestScan?.status == "running" || appState.latestScan?.status == "applying" {
                try? await Task.sleep(nanoseconds: 1_500_000_000)
                if Task.isCancelled { break }
                await appState.refreshLatestScan()
            }
            if appState.latestScan?.status == "applied" {
                await appState.refreshStats(days: appState.selectedStatsDays)
                await appState.refreshAbuseQueue()
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
        } else if let job = appState.latestScan, job.status == "applying" {
            ProgressView().controlSize(.small)
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
                if job.status == "running" || job.status == "applying" {
                    ProgressView().controlSize(.small)
                } else if job.status == "completed" || job.status == "applied" {
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

            if (job.status == "running" && job.totalMessages == 0) || job.status == "applying" {
                ProgressView()
                    .progressViewStyle(.linear)
            } else {
                ProgressView(value: job.progressFraction)
            }

            if job.dryRun && job.status == "completed" && job.spamFound > 0 {
                HStack(spacing: 10) {
                    Text("Ready to apply these \(job.spamFound) verdicts without re-running Jev.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button(applyButtonTitle(spamCount: job.spamFound)) {
                        Task { await applyScan(job.id) }
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                    .disabled(isSubmitting)
                }
                .padding(.top, 2)
            }

            if job.status == "applied" {
                Text("Applied dry run results (\(job.spamFound) spam \(job.spamFound == 1 ? "email" : "emails") processed) and updated stats.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
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

            if job.spamFound > 0 {
                matchedEmails(job)
            }
        }
    }

    private func matchedEmails(_ job: ScanJob) -> some View {
        DisclosureGroup(isExpanded: $showMatches) {
            Group {
                if matches.isEmpty {
                    ProgressView()
                        .controlSize(.small)
                        .frame(maxWidth: .infinity, minHeight: 60)
                } else {
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 8) {
                            ForEach(matches) { match in
                                matchRow(match)
                            }
                        }
                        .padding(.vertical, 6)
                        .padding(.trailing, 12)
                    }
                    .frame(height: 280)
                }
            }
            .padding(.top, 4)
        } label: {
            Text("Matched Emails (\(job.spamFound))")
        }
        .font(.caption)
        .task(id: "\(job.id)-\(job.status)-\(job.spamFound)") {
            await loadMatches(job)
        }
    }

    private func matchRow(_ match: ScanMatch) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(match.subject.isEmpty ? "(No subject)" : match.subject)
                    .font(.caption.weight(.medium))
                    .lineLimit(1)
                Text("\(match.mailbox ?? "INBOX") · \(match.sender)")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            if match.action == "delete" {
                Image(systemName: "trash.slash")
                    .font(.caption2)
                    .foregroundStyle(.red)
                    .help("Deletes permanently")
            }
            Text("\(match.categoryID) · \(Int(match.confidence * 100))%")
                .font(.caption2.monospacedDigit())
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(Color.orange.opacity(0.15), in: Capsule())
        }
    }

    private func loadMatches(_ job: ScanJob) async {
        guard let client = appState.apiClient else { return }
        if matchesJobID != job.id {
            matches = []
            matchesJobID = job.id
        }
        if let loaded = try? await client.scanMatches(id: job.id) {
            matches = loaded
        }
    }

    private func statusHeadline(_ job: ScanJob) -> String {
        let mode = job.dryRun ? "Dry Run" : "Live"
        if job.status == "applying" {
            if let folder = job.currentMailbox, !folder.isEmpty {
                return "Applying results in \(folder)..."
            }
            return "Applying dry run results..."
        }
        if job.status == "applied" {
            return "Applied (\(job.dateRange))"
        }
        if job.status == "running", let folder = job.currentMailbox, !folder.isEmpty {
            return "Scanning \(folder) (\(mode), \(job.dateRange))"
        }
        return "\(job.status.capitalized) (\(mode), \(job.dateRange))"
    }

    private func applyButtonTitle(spamCount: Int) -> String {
        let deletes = matches.filter { $0.action == "delete" }.count
        guard deletes > 0, matches.count == spamCount else {
            return "Apply: Move \(spamCount) to Trash"
        }
        if deletes == spamCount {
            return "Apply: Delete \(spamCount) Permanently"
        }
        return "Apply: Trash \(spamCount - deletes), Delete \(deletes)"
    }

    private func applyScan(_ id: String) async {
        guard let client = appState.apiClient else { return }
        errorMessage = nil
        isSubmitting = true
        defer { isSubmitting = false }
        do {
            appState.latestScan = try await client.applyScan(id: id)
        } catch {
            errorMessage = error.localizedDescription
        }
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

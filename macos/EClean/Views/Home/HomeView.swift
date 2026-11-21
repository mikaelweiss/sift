import Charts
import SwiftUI

struct HomeView: View {
    @Environment(AppState.self) private var appState
    @State private var selectedDays = 30

    private let dayOptions: [(label: String, days: Int)] = [
        ("7 Days", 7),
        ("30 Days", 30),
        ("90 Days", 90),
        ("All Time", 0),
    ]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                statusHeader

                if appState.serverUpdateAvailable {
                    updateBanner
                }

                if let err = appState.errorMessage {
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.circle.fill")
                            .foregroundStyle(.red)
                        Text(err)
                            .font(.callout)
                        Spacer()
                        Button("Retry") {
                            Task { await appState.refreshAll() }
                        }
                        .controlSize(.small)
                    }
                    .padding(12)
                    .background(Color.red.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
                }

                summaryCards
                chartSection
            }
            .padding(24)
        }
        .onChange(of: selectedDays) { _, newValue in
            Task { await appState.refreshStats(days: newValue) }
        }
    }

    private var statusHeader: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Spam Protection")
                    .font(.title2.bold())
                HStack(spacing: 12) {
                    statusPill(
                        label: appState.isConnected ? "Server Online" : "Server Offline",
                        color: appState.isConnected ? .green : .red
                    )
                    if let health = appState.health {
                        statusPill(
                            label: health.imapConnected ? "iCloud IMAP IDLE Active" : "IMAP Disconnected",
                            color: health.imapConnected ? .green : .orange
                        )
                        Text("\(appState.connection?.host ?? "") · v\(health.version) (\(health.os)/\(health.arch))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            Spacer()
            Button {
                Task { await appState.refreshAll() }
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
        }
    }

    private func statusPill(label: String, color: Color) -> some View {
        HStack(spacing: 6) {
            Circle()
                .fill(color)
                .frame(width: 8, height: 8)
            Text(label)
                .font(.caption.weight(.medium))
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(color.opacity(0.12), in: Capsule())
    }

    private var updateBanner: some View {
        HStack(spacing: 12) {
            Image(systemName: "arrow.down.circle.fill")
                .font(.title3)
                .foregroundStyle(Color.accentColor)
            VStack(alignment: .leading, spacing: 2) {
                Text("Server Update Available (v\(appState.bundledServerVersion))")
                    .font(.headline)
                Text(appState.isUpdatingServer ? appState.updateProgressMessage : "Your app includes a newer eclean server binary. Updating preserves all SQLite data.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if appState.isUpdatingServer {
                ProgressView().controlSize(.small)
            } else {
                Button("Update Server") {
                    Task { await appState.updateServerBinary() }
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(14)
        .background(Color.accentColor.opacity(0.1), in: RoundedRectangle(cornerRadius: 10))
    }

    private var summaryCards: some View {
        HStack(spacing: 16) {
            metricCard(
                title: "Blocked Emails",
                value: "\(appState.totalBlocked)",
                subtitle: selectedDays == 0 ? "All recorded history" : "Last \(selectedDays) days",
                icon: "shield.checkmark.fill",
                color: .blue
            )
            metricCard(
                title: "Active Categories",
                value: "\(appState.categories.filter(\.enabled).count)",
                subtitle: appState.settings.spamAction == "delete" ? "Mode: Delete Permanently" : "Mode: Move to Trash",
                icon: "tag.fill",
                color: .purple
            )
            metricCard(
                title: "Pending Abuse Reports",
                value: "\(appState.abuseQueue.count)",
                subtitle: appState.settings.abuseEnabled ? "Click yellow icon to review" : "Disabled in Features",
                icon: "exclamationmark.triangle.fill",
                color: .yellow
            )
        }
    }

    private func metricCard(title: String, value: String, subtitle: String, icon: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: icon)
                    .foregroundStyle(color)
                Text(title)
                    .font(.subheadline.weight(.medium))
                    .foregroundStyle(.secondary)
            }
            Text(value)
                .font(.system(size: 28, weight: .bold, design: .rounded))
            Text(subtitle)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
    }

    private var chartSection: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Text("Blocked Spam by Category Over Time")
                        .font(.headline)
                    Spacer()
                    Picker("Range", selection: $selectedDays) {
                        ForEach(dayOptions, id: \.days) { opt in
                            Text(opt.label).tag(opt.days)
                        }
                    }
                    .pickerStyle(.segmented)
                    .frame(width: 300)
                }

                if appState.stats.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: "chart.bar.xaxis")
                            .font(.largeTitle)
                            .foregroundStyle(.secondary)
                        Text("No blocked spam recorded in this timeframe yet.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                        Text("Run a Historical Inbox Scan in Features to backfill past trends.")
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                    .frame(maxWidth: .infinity, minHeight: 240)
                } else {
                    Chart(appState.stats) { item in
                        BarMark(
                            x: .value("Day", item.parsedDate, unit: .day),
                            y: .value("Blocked", item.count)
                        )
                        .foregroundStyle(by: .value("Category", item.categoryName))
                    }
                    .chartLegend(position: .bottom)
                    .frame(height: 260)
                }
            }
            .padding(8)
        }
    }
}

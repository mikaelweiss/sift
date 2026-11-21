import Charts
import SwiftUI

struct HomeView: View {
    @Environment(AppState.self) private var appState
    @State private var selectedDays = 30

    private let dayOptions: [(label: String, days: Int)] = [
        ("7D", 7),
        ("30D", 30),
        ("90D", 90),
        ("1Y", 365),
        ("All", 0),
    ]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
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
                    .background(Color.red.opacity(0.1), in: RoundedRectangle(cornerRadius: 10))
                }

                chartCard
                HistoricalScanView()
            }
            .padding(24)
        }
        .onChange(of: selectedDays) { _, newValue in
            Task { await appState.refreshStats(days: newValue) }
        }
    }

    private var updateBanner: some View {
        HStack(spacing: 12) {
            Image(systemName: "arrow.down.circle.fill")
                .font(.title3)
                .foregroundStyle(Color.accentColor)
            VStack(alignment: .leading, spacing: 2) {
                Text("Server Update Available (v\(appState.bundledServerVersion))")
                    .font(.headline)
                Text(appState.isUpdatingServer ? appState.updateProgressMessage : "Update the sift binary on your server while keeping all SQLite data.")
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

    private var chartCard: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text("\(appState.totalBlocked)")
                            .font(.system(size: 32, weight: .bold, design: .rounded))
                            .monospacedDigit()
                        Text(appState.totalBlocked == 1 ? "spam email blocked" : "spam emails blocked")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    Text(timeframeSubtitle)
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }

                Spacer()

                Picker("Range", selection: $selectedDays) {
                    ForEach(dayOptions, id: \.days) { opt in
                        Text(opt.label).tag(opt.days)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 260)
            }

            if appState.stats.isEmpty {
                VStack(spacing: 6) {
                    Image(systemName: "chart.bar.xaxis")
                        .font(.title)
                        .foregroundStyle(.tertiary)
                    Text("No blocked spam in this timeframe yet")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, minHeight: 220)
            } else {
                SpamChart(stats: appState.stats, categories: appState.categories, rangeDays: appState.selectedStatsDays)
            }
        }
        .padding(20)
        .background(Color.secondary.opacity(0.06), in: RoundedRectangle(cornerRadius: 12))
    }

    private var timeframeSubtitle: String {
        let mode = appState.settings.deleteEnabled ? "Junk + permanent delete" : "Move to Junk"
        let activeCount = appState.categories.filter(\.enabled).count
        let range = switch selectedDays {
        case 0: "All time"
        case 365: "Last year"
        default: "Last \(selectedDays) days"
        }
        return "\(range) · \(activeCount) active categories · \(mode)"
    }
}

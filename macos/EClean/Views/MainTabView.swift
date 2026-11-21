import SwiftUI

struct MainTabView: View {
    @Environment(AppState.self) private var appState
    @State private var showAbuseReview = false

    var body: some View {
        @Bindable var bindableState = appState
        let hasQueuedDomains = !appState.abuseQueue.isEmpty

        NavigationStack {
            HomeView()
                .navigationTitle("EClean")
                .toolbar {
                    ToolbarItem(placement: .navigation) {
                        HStack(spacing: 6) {
                            Circle()
                                .fill(statusColor)
                                .frame(width: 7, height: 7)
                            Text(statusText)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .padding(.horizontal, 8)
                    }

                    ToolbarItemGroup(placement: .primaryAction) {
                        Button {
                            showAbuseReview = true
                        } label: {
                            if hasQueuedDomains {
                                HStack(spacing: 4) {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .foregroundStyle(.yellow)
                                    Text("\(appState.abuseQueue.count)")
                                        .font(.caption.bold().monospacedDigit())
                                        .padding(.horizontal, 5)
                                        .padding(.vertical, 1)
                                        .background(Color.yellow.opacity(0.25), in: Capsule())
                                }
                            } else {
                                Image(systemName: "exclamationmark.triangle")
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .disabled(!hasQueuedDomains)
                        .help(hasQueuedDomains ? "Review domains queued for abuse reporting" : "No domains queued for abuse reporting")

                        Button {
                            appState.showSettings = true
                        } label: {
                            Image(systemName: "gearshape")
                        }
                        .help("Settings (⌘,)")
                    }
                }
                .sheet(isPresented: $showAbuseReview) {
                    AbuseReviewSheet()
                        .environment(appState)
                }
                .sheet(isPresented: $bindableState.showSettings) {
                    SettingsSheet()
                        .environment(appState)
                }
        }
    }

    private var statusColor: Color {
        guard appState.isConnected else { return .red }
        if appState.health?.imapConnected == true { return .green }
        return .orange
    }

    private var statusText: String {
        guard appState.isConnected else { return "Offline" }
        let host = appState.connection?.host.components(separatedBy: ".").first ?? "Server"
        if appState.health?.imapConnected == true {
            return "\(host) · Active"
        }
        return "\(host) · IMAP Disconnected"
    }
}

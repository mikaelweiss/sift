import SwiftUI

private enum AppTab: Hashable {
    case home
    case features
}

struct MainTabView: View {
    @Environment(AppState.self) private var appState
    @State private var selectedTab: AppTab = .home
    @State private var showAbuseReview = false

    var body: some View {
        @Bindable var bindableState = appState
        let hasQueuedDomains = !appState.abuseQueue.isEmpty

        NavigationStack {
            TabView(selection: $selectedTab) {
                HomeView()
                    .tabItem {
                        Label("Home", systemImage: "chart.bar.xaxis")
                    }
                    .tag(AppTab.home)

                FeaturesView()
                    .tabItem {
                        Label("Features", systemImage: "sparkles")
                    }
                    .tag(AppTab.features)
            }
            .padding(.top, 8)
            .toolbar {
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
}

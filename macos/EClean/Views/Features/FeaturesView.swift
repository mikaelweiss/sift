import SwiftUI

struct FeaturesView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Features")
                        .font(.title2.bold())
                    Text("Clean up your historical inbox and configure deterministic abuse reporting.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }

                HistoricalScanView()
                AbuseReportingSetupView()
            }
            .padding(24)
        }
    }
}

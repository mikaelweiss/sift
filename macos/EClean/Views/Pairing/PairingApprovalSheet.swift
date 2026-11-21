import SwiftUI

struct PairingApprovalSheet: View {
    @Environment(AppState.self) private var appState
    let request: IncomingPairRequest
    @State private var isSubmitting = false

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "laptopcomputer.and.iphone")
                .font(.system(size: 40))
                .foregroundStyle(Color.accentColor)

            Text("Pair New Mac?")
                .font(.title2.bold())

            Text("\"\(request.deviceName)\" wants to connect to your EClean server. Confirm this code matches the screen on that Mac:")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .frame(maxWidth: 360)

            Text(request.verificationCode)
                .font(.system(size: 36, weight: .bold, design: .monospaced))
                .tracking(8)
                .padding(.vertical, 8)
                .padding(.horizontal, 20)
                .background(Color.secondary.opacity(0.1), in: RoundedRectangle(cornerRadius: 10))

            HStack(spacing: 12) {
                Button("Deny", role: .destructive) {
                    Task {
                        isSubmitting = true
                        await appState.approveIncomingPair(approve: false)
                        isSubmitting = false
                    }
                }
                .disabled(isSubmitting)

                Button("Approve") {
                    Task {
                        isSubmitting = true
                        await appState.approveIncomingPair(approve: true)
                        isSubmitting = false
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(isSubmitting)
            }
        }
        .padding(28)
        .frame(width: 440)
    }
}

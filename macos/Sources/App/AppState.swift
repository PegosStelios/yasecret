import Foundation

@Observable
final class AppState {
    var session: YasecretSession?
    var isLocked: Bool = true
    var mcpSessionCount: Int = 0
    private var mcpPollTimer: Timer?

    func startMcpPolling() {
        mcpPollTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
            self?.pollMcpSession()
        }
    }

    func stopMcpPolling() {
        mcpPollTimer?.invalidate()
        mcpPollTimer = nil
    }

    private func pollMcpSession() {
        // Polling impl added in Task 7
    }
}

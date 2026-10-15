import Foundation

@Observable
final class AppState {
    var session: YasecretSession?
    var isLocked: Bool = true
    var mcpSessionCount: Int = 0
    private var lastKnownMcpCount: Int = 0
    private var mcpPollTimer: Timer?

    func startMcpPolling() {
        NotificationService.shared.requestPermission()
        if let count = try? session?.mcpSessionCount() {
            lastKnownMcpCount = Int(count)
        }
        mcpPollTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
            self?.pollMcpSession()
        }
    }

    func stopMcpPolling() {
        mcpPollTimer?.invalidate()
        mcpPollTimer = nil
    }

    private func pollMcpSession() {
        guard let session else { return }
        guard let rawCount = try? session.mcpSessionCount() else { return }
        let count = Int(rawCount)
        if count > lastKnownMcpCount {
            lastKnownMcpCount = count
            mcpSessionCount = count
            NotificationService.shared.notifyMcpAccess()
        }
    }
}

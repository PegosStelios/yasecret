import Foundation
import AppKit

@MainActor
@Observable
final class AppState {
    var session: YasecretSession?
    var isLocked: Bool = true
    var mcpSessionCount: Int = 0
    private var lastKnownMcpCount: Int = 0
    private var mcpPollTimer: Timer?
    private var lockObservers: [NSObjectProtocol] = []

    init() {
        installAutoLock()
    }

    func lock() {
        stopMcpPolling()
        session = nil
        isLocked = true
    }

    /// Locks the vault when the Mac sleeps, the screen locks, or the user switches accounts.
    private func installAutoLock() {
        let ws = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.willSleepNotification,
                     NSWorkspace.screensDidSleepNotification,
                     NSWorkspace.sessionDidResignActiveNotification] {
            lockObservers.append(ws.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in self?.lock() }
            })
        }
        lockObservers.append(DistributedNotificationCenter.default().addObserver(
            forName: .init("com.apple.screenIsLocked"), object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.lock() }
        })
    }

    func startMcpPolling() {
        NotificationService.shared.requestPermission()
        if let count = try? session?.mcpSessionCount() {
            lastKnownMcpCount = Int(count)
        }
        mcpPollTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
            guard let self else { return }
            Task { @MainActor in self.pollMcpSession() }
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

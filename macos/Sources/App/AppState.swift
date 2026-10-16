import Foundation
import AppKit

@MainActor
@Observable
final class AppState {
    var session: YasecretSession?
    var isLocked: Bool = true
    var mcpSessionCount: Int = 0
    /// Bumped whenever another device's changes landed in the vault; views reload on change.
    var dataRevision = 0
    var syncRunning = false
    var syncError: String?
    /// A yasecret://join link opened from outside the app, waiting for the Join sheet.
    var pendingJoinLink: String?
    private var lastSyncRevision: UInt64 = 0
    private var syncTimer: Timer?
    private var lastKnownMcpCount: Int = 0
    private var mcpPollTimer: Timer?
    private var lockObservers: [NSObjectProtocol] = []

    init() {
        installAutoLock()
    }

    func didUnlock() {
        startMcpPolling()
        startSync()
    }

    func lock() {
        stopMcpPolling()
        syncTimer?.invalidate()
        syncTimer = nil
        // Synchronous so a quick re-unlock can reopen the sync stores.
        session?.stopSync()
        syncRunning = false
        session = nil
        isLocked = true
    }

    private func startSync() {
        guard let session else { return }
        let name = Host.current().localizedName ?? "Mac"
        Task.detached {
            do {
                try session.startSync(deviceName: name)
                await MainActor.run {
                    self.syncRunning = true
                    self.syncError = nil
                    self.startRevisionPolling()
                }
            } catch {
                let msg = userMessage(error)
                await MainActor.run { self.syncError = msg }
            }
        }
    }

    private func startRevisionPolling() {
        syncTimer?.invalidate()
        syncTimer = Timer.scheduledTimer(withTimeInterval: 1.5, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self, let session = self.session else { return }
                let rev = session.syncRevision()
                if rev != self.lastSyncRevision {
                    self.lastSyncRevision = rev
                    self.dataRevision += 1
                }
            }
        }
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

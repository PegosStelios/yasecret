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
        #if DEBUG
        if let look = ProcessInfo.processInfo.environment["YASECRET_DEV_APPEARANCE"] {
            DispatchQueue.main.async {
                NSApp.appearance = NSAppearance(named: look == "light" ? .aqua : .darkAqua)
            }
        }
        #endif
    }

    func didUnlock() {
        startMcpPolling()
        startSync()
        checkExpiry()
    }

    /// Reminds about variables that expired or expire within a week.
    func checkExpiry() {
        guard let session else { return }
        Task.detached {
            let now = Int64(Date().timeIntervalSince1970)
            var items: [(id: String, label: String, expired: Bool)] = []
            for p in (try? session.listProjects()) ?? [] {
                for e in (try? session.listEnvironments(projectId: p.id)) ?? [] {
                    for s in (try? session.listSecrets(envId: e.id)) ?? [] {
                        guard let exp = s.expiresAt, exp < now + 7 * 86_400 else { continue }
                        items.append((s.id, "\(s.key) (\(p.name)/\(e.name))", exp <= now))
                    }
                }
            }
            if !items.isEmpty { NotificationService.shared.notifyExpiring(items) }
        }
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
        var name = Host.current().localizedName ?? "Mac"
        #if DEBUG
        if let override = ProcessInfo.processInfo.environment["YASECRET_DEV_DEVICE_NAME"] { name = override }
        #endif
        Task.detached {
            do {
                try session.startSync(deviceName: name)
                await MainActor.run {
                    // Locked (or re-unlocked) while starting: this session is gone, shut it down.
                    guard self.session === session else {
                        session.stopSync()
                        return
                    }
                    self.syncRunning = true
                    self.syncError = nil
                    self.startRevisionPolling()
                }
            } catch {
                let msg = userMessage(error)
                await MainActor.run { if self.session === session { self.syncError = msg } }
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

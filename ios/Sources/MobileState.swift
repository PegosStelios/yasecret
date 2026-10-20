import Foundation
import LocalAuthentication
import UIKit

/// Vault session for the phone: unlock (password or Face ID), sync while open, lock in the background.
@MainActor
@Observable
final class MobileState {
    var session: YasecretSession?
    var isFirstRun = !FileManager.default.fileExists(atPath: MobileState.dbPath)
    var error: String?
    var busy = false
    /// Bumped when synced changes land; lists reload on change.
    var revision = 0
    var pendingJoinLink: String?
    private var timer: Timer?
    private var lastRevision: UInt64 = 0
    private let keychain = KeychainService(account: "mobile")

    static let dbPath: String = {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("db.sqlite").path
    }()

    var canUseBiometrics: Bool {
        !isFirstRun && keychain.load() != nil && LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    init() {
        NotificationCenter.default.addObserver(forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.lock() }
        }
    }

    func unlock(password: String) async {
        busy = true
        error = nil
        defer { busy = false }
        let path = Self.dbPath
        do {
            let opened = try await Task.detached { try YasecretSession(dbPath: path, password: password) }.value
            keychain.save(password: password)
            session = opened
            isFirstRun = false
            startSync(opened)
        } catch FfiError.WrongPassword {
            error = "Wrong password — try again"
        } catch {
            self.error = describe(error)
        }
    }

    func unlockWithBiometrics() async {
        guard let stored = keychain.load() else { return }
        let context = LAContext()
        do {
            let ok = try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Unlock your vault")
            if ok { await unlock(password: stored) }
        } catch {
            // Cancelled or unavailable: the password field stays.
        }
    }

    func lock() {
        timer?.invalidate()
        timer = nil
        session?.stopSync()
        session = nil
    }

    private func startSync(_ session: YasecretSession) {
        let name = UIDevice.current.name
        Task.detached {
            try? session.startSync(deviceName: name)
        }
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self, let session = self.session else { return }
                let rev = session.syncRevision()
                if rev != self.lastRevision {
                    self.lastRevision = rev
                    self.revision += 1
                }
            }
        }
    }
}

func describe(_ error: Error) -> String {
    switch error {
    case FfiError.WrongPassword: return "Wrong password"
    case FfiError.NotFound(let msg): return "Not found: \(msg)"
    case FfiError.PermissionDenied: return "You have view-only access"
    case FfiError.Crypto: return "Couldn't decrypt this value"
    case FfiError.Io(let msg), FfiError.Db(let msg), FfiError.Parse(let msg), FfiError.Sync(let msg): return msg
    default: return error.localizedDescription
    }
}

/// Copies text; secrets expire from the clipboard after a minute.
func copyToClipboard(_ text: String, sensitive: Bool) {
    if sensitive {
        UIPasteboard.general.setItems([[UIPasteboard.typeAutomatic: text]], options: [.expirationDate: Date().addingTimeInterval(60), .localOnly: true])
    } else {
        UIPasteboard.general.string = text
    }
}

import Foundation

@MainActor
@Observable
final class UnlockViewModel {
    var password: String = ""
    var confirmPassword: String = ""
    var errorMessage: String?
    var isUnlocking: Bool = false
    var isFirstRun: Bool

    private let appState: AppState
    private let dbPath: String
    private let keychain: KeychainService
    private let biometrics = BiometricService()

    init(appState: AppState, dbPath: String, keychainAccount: String = "default") {
        self.appState = appState
        self.dbPath = dbPath
        self.keychain = KeychainService(account: keychainAccount)
        self.isFirstRun = !FileManager.default.fileExists(atPath: dbPath)
    }

    func tryBiometricUnlock() async {
        guard !isFirstRun, let stored = keychain.load() else { return }
        let ok = await biometrics.authenticate()
        guard ok else { return }
        await unlock(with: stored)
    }

    func unlock() async {
        await unlock(with: password)
    }

    private func unlock(with pw: String) async {
        if isFirstRun && pw != confirmPassword {
            errorMessage = "Passwords don't match — confirm your master password"
            return
        }
        isUnlocking = true
        errorMessage = nil
        defer { isUnlocking = false }
        do {
            let session = try YasecretSession(dbPath: dbPath, password: pw)
            keychain.save(password: pw)
            appState.session = session
            appState.isLocked = false
            isFirstRun = false
            appState.startMcpPolling()
        } catch {
            errorMessage = "Wrong password — try again"
            appState.session = nil
            appState.isLocked = true
        }
    }
}

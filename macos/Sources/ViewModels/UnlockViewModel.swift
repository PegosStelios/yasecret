import Foundation

@Observable
final class UnlockViewModel {
    var password: String = ""
    var errorMessage: String?
    var isUnlocking: Bool = false

    private let appState: AppState
    private let dbPath: String
    private let keychain = KeychainService()
    private let biometrics = BiometricService()

    init(appState: AppState, dbPath: String) {
        self.appState = appState
        self.dbPath = dbPath
    }

    func tryBiometricUnlock() async {
        guard let stored = keychain.load() else { return }
        let ok = await biometrics.authenticate()
        guard ok else { return }
        await unlock(with: stored)
    }

    func unlock() async {
        await unlock(with: password)
    }

    private func unlock(with pw: String) async {
        isUnlocking = true
        errorMessage = nil
        defer { isUnlocking = false }
        do {
            let session = try YasecretSession(dbPath: dbPath, password: pw)
            keychain.save(password: pw)
            appState.session = session
            appState.isLocked = false
            appState.startMcpPolling()
        } catch {
            errorMessage = "Wrong password — try again"
            appState.session = nil
            appState.isLocked = true
        }
    }
}

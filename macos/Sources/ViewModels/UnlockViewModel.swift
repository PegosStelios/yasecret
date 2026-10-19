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
        // The unit-test host is this app; it must never unlock the real vault.
        guard ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] == nil,
              ProcessInfo.processInfo.environment["YASECRET_DB_PATH"] == nil else { return }
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
            errorMessage = "Passwords don't match — type the same password in both fields"
            return
        }
        isUnlocking = true
        errorMessage = nil
        defer { isUnlocking = false }
        let path = dbPath
        // Opening the vault runs the key derivation; keep it off the main thread.
        let result = await Task.detached { () -> Result<YasecretSession, Error> in
            Result { try YasecretSession(dbPath: path, password: pw) }
        }.value
        switch result {
        case .success(let session):
            keychain.save(password: pw)
            appState.session = session
            appState.isLocked = false
            isFirstRun = false
            appState.didUnlock()
        case .failure(let error):
            if case FfiError.WrongPassword = error {
                errorMessage = "Wrong password — try again"
            } else {
                errorMessage = "Couldn't open the vault: \(userMessage(error))"
            }
            appState.session = nil
            appState.isLocked = true
        }
    }
}

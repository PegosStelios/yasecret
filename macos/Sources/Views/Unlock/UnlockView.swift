import SwiftUI

struct UnlockView: View {
    @Environment(AppState.self) private var appState
    @State private var vm: UnlockViewModel?

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "lock.fill")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)

            Text("Yasecret")
                .font(.largeTitle.bold())

            if let vm {
                if vm.isFirstRun {
                    Text("Create your master password")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }

                SecureField("Master password", text: Bindable(vm).password)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 260)
                    .onSubmit { Task { await vm.unlock() } }

                if vm.isFirstRun {
                    SecureField("Confirm password", text: Bindable(vm).confirmPassword)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 260)
                }

                if let err = vm.errorMessage {
                    Text(err).foregroundStyle(.red).font(.caption)
                }

                Button(vm.isUnlocking ? "Unlocking…" : (vm.isFirstRun ? "Create Vault" : "Unlock")) {
                    Task { await vm.unlock() }
                }
                .disabled(vm.isUnlocking || vm.password.isEmpty ||
                          (vm.isFirstRun && vm.confirmPassword.isEmpty))
                .buttonStyle(.borderedProminent)
            }
        }
        .frame(width: 360, height: 320)
        .task {
            // Debug builds can open a throwaway vault (and Keychain slot) for UI testing.
            #if DEBUG
            let override = ProcessInfo.processInfo.environment["YASECRET_DB_PATH"]
            #else
            let override: String? = nil
            #endif
            let dbPath = override ?? defaultDbPath()
            let newVm = UnlockViewModel(appState: appState, dbPath: dbPath,
                                        keychainAccount: override.map { "dev-\($0)" } ?? "default")
            vm = newVm
            #if DEBUG
            if override != nil, let pw = ProcessInfo.processInfo.environment["YASECRET_DEV_PASSWORD"] {
                newVm.password = pw
                newVm.confirmPassword = pw
                await newVm.unlock()
                return
            }
            #endif
            await newVm.tryBiometricUnlock()
        }
    }
}

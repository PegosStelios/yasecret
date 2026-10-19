import SwiftUI

struct UnlockView: View {
    @Environment(AppState.self) private var appState
    @State private var vm: UnlockViewModel?
    @FocusState private var focus: Field?

    private enum Field { case password, confirm }

    private func canSubmit(_ vm: UnlockViewModel) -> Bool {
        !vm.isUnlocking && !vm.password.isEmpty && (!vm.isFirstRun || !vm.confirmPassword.isEmpty)
    }

    private func submit(_ vm: UnlockViewModel) {
        guard canSubmit(vm) else { return }
        Task { await vm.unlock() }
    }

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "lock.fill")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)

            Text("Yasecret")
                .font(.largeTitle.bold())

            if let vm {
                Text(vm.isFirstRun ? "Create a master password for your vault" : "Enter your master password")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                SecureField("Master password", text: Bindable(vm).password)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 260)
                    .focused($focus, equals: .password)
                    .onSubmit {
                        // On first run Return moves on to the confirmation field instead of failing.
                        if vm.isFirstRun { focus = .confirm } else { submit(vm) }
                    }

                if vm.isFirstRun {
                    SecureField("Confirm password", text: Bindable(vm).confirmPassword)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 260)
                        .focused($focus, equals: .confirm)
                        .onSubmit { submit(vm) }
                }

                if let err = vm.errorMessage {
                    Text(err)
                        .foregroundStyle(.red)
                        .font(.callout)
                        .multilineTextAlignment(.center)
                        .frame(width: 280)
                }

                Button {
                    submit(vm)
                } label: {
                    HStack(spacing: 6) {
                        if vm.isUnlocking { ProgressView().controlSize(.small) }
                        Text(vm.isUnlocking ? "Unlocking…" : (vm.isFirstRun ? "Create Vault" : "Unlock"))
                    }
                    .frame(minWidth: 120)
                }
                .disabled(!canSubmit(vm))
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
            }
        }
        .disabled(vm?.isUnlocking == true)
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
            focus = .password
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

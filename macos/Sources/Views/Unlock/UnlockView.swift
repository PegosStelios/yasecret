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
                SecureField("Master password", text: Bindable(vm).password)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 260)
                    .onSubmit { Task { await vm.unlock() } }

                if let err = vm.errorMessage {
                    Text(err).foregroundStyle(.red).font(.caption)
                }

                Button(vm.isUnlocking ? "Unlocking…" : "Unlock") {
                    Task { await vm.unlock() }
                }
                .disabled(vm.isUnlocking || vm.password.isEmpty)
                .buttonStyle(.borderedProminent)
            }
        }
        .frame(width: 360, height: 320)
        .task {
            let dbPath = defaultDbPath()
            let newVm = UnlockViewModel(appState: appState, dbPath: dbPath)
            vm = newVm
            await newVm.tryBiometricUnlock()
        }
    }
}

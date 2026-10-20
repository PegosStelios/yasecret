import SwiftUI

struct UnlockView: View {
    @Environment(MobileState.self) private var state
    @State private var password = ""
    @State private var confirm = ""
    @FocusState private var focused: Bool

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "lock.fill").font(.system(size: 44)).foregroundStyle(.secondary)
            Text("Yasecret").font(.largeTitle.bold())
            Text(state.isFirstRun
                 ? "Create a master password for the vault on this device. You'll join shared projects next."
                 : "Enter your master password")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            SecureField("Master password", text: $password)
                .textFieldStyle(.roundedBorder)
                .focused($focused)
                .submitLabel(.go)
                .onSubmit(submit)
            if state.isFirstRun {
                SecureField("Confirm password", text: $confirm).textFieldStyle(.roundedBorder)
            }
            if let error = state.error {
                Text(error).font(.callout).foregroundStyle(.red)
            }
            Button(action: submit) {
                Text(state.busy ? "Unlocking…" : (state.isFirstRun ? "Create Vault" : "Unlock")).frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(state.busy || password.isEmpty || (state.isFirstRun && password != confirm))
            if state.canUseBiometrics {
                Button {
                    Task { await state.unlockWithBiometrics() }
                } label: {
                    Label("Unlock with Face ID", systemImage: "faceid")
                }
            }
        }
        .padding(32)
        .frame(maxWidth: 420)
        .task {
            if state.canUseBiometrics { await state.unlockWithBiometrics() } else { focused = true }
        }
    }

    private func submit() {
        guard !password.isEmpty, !state.isFirstRun || password == confirm else { return }
        Task { await state.unlock(password: password) }
    }
}

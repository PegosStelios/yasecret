import SwiftUI

struct NewSecretView: View {
    let projectId: String
    let envId: String
    var vm: SecretsViewModel
    let session: YasecretSession
    @Environment(\.dismiss) private var dismiss

    @State private var key = ""
    @State private var value = ""
    @State private var errorMsg: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("New Secret")
                .font(.headline)

            TextField("KEY_NAME", text: $key)
                .textFieldStyle(.roundedBorder)
                .font(.system(.body, design: .monospaced))

            SecureField("Value", text: $value)
                .textFieldStyle(.roundedBorder)

            if let err = errorMsg {
                Text(err).foregroundStyle(.red).font(.caption)
            }

            HStack {
                Button("Cancel") { dismiss() }
                Spacer()
                Button("Add Secret") {
                    guard !key.isEmpty, !value.isEmpty else {
                        errorMsg = "Key and value are required"; return
                    }
                    vm.createSecret(
                        projectId: projectId, envId: envId,
                        key: key, value: value, expiresAt: nil, session: session)
                    if vm.errorMessage != nil {
                        errorMsg = vm.errorMessage
                    } else {
                        dismiss()
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(key.isEmpty || value.isEmpty)
            }
        }
        .padding(24)
        .frame(width: 360)
    }
}

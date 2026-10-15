import SwiftUI

struct EditorRequest: Identifiable {
    let id = UUID()
    /// nil means "add a new variable".
    let secret: FfiSecret?
}

struct SecretEditorView: View {
    let request: EditorRequest
    let projectId: String
    let envId: String
    let vm: SecretsViewModel
    let session: YasecretSession
    var onSaved: () -> Void = {}
    @Environment(\.dismiss) private var dismiss

    @State private var key = ""
    @State private var value = ""
    @State private var originalValue = ""
    @State private var isSecret = true
    @State private var kindTouched = false
    @State private var showValue = false
    @State private var error: String?

    private var existing: FfiSecret? { request.secret }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(existing == nil ? "Add Variable" : "Edit Variable")
                .font(.title3.bold())

            VStack(alignment: .leading, spacing: 4) {
                Text("Key").font(.caption).foregroundStyle(.secondary)
                TextField("API_KEY", text: $key)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
                    .onChange(of: key) { _, new in
                        if existing == nil && !kindTouched { isSecret = looksSecret(key: new) }
                    }
                if !key.isEmpty && !isValidKey(key: key) {
                    Text("Use letters, digits and _ — can't start with a digit or contain spaces")
                        .font(.caption).foregroundStyle(.red)
                }
            }

            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text("Value").font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    if isSecret {
                        Button(showValue ? "Hide" : "Show") { showValue.toggle() }
                            .buttonStyle(.link)
                            .font(.caption)
                    }
                }
                if isSecret && !showValue {
                    SecureField("Value", text: $value)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.body, design: .monospaced))
                } else {
                    TextEditor(text: $value)
                        .font(.system(.body, design: .monospaced))
                        .scrollContentBackground(.hidden)
                        .padding(4)
                        .frame(minHeight: 56, maxHeight: 140)
                        .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
                        .overlay(RoundedRectangle(cornerRadius: 6).stroke(.separator))
                }
            }

            Toggle(isOn: Binding(get: { isSecret }, set: { isSecret = $0; kindTouched = true })) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Secret")
                    Text(isSecret
                         ? "Value is masked until you reveal it."
                         : "Plain variable — value is shown in the list.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .toggleStyle(.switch)

            if let error {
                Text(error).font(.callout).foregroundStyle(.red)
            }

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(existing == nil ? "Add" : "Save", action: save)
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(!isValidKey(key: key))
            }
        }
        .padding(20)
        .frame(width: 460)
        .onAppear(perform: prefill)
    }

    private func prefill() {
        guard let s = existing else { return }
        key = s.key
        isSecret = s.isSecret
        let current = (try? session.getSecretPlaintext(projectId: projectId, secretId: s.id)) ?? ""
        value = current
        originalValue = current
    }

    private func save() {
        let ok: Bool
        if let s = existing {
            ok = vm.editSecret(projectId: projectId, secret: s, newKey: key,
                               newValue: value == originalValue ? nil : value,
                               isSecret: isSecret, session: session)
        } else {
            ok = vm.createSecret(projectId: projectId, envId: envId, key: key, value: value,
                                 isSecret: isSecret, session: session)
        }
        if ok {
            onSaved()
            dismiss()
        } else {
            error = vm.errorMessage
            vm.errorMessage = nil
        }
    }
}

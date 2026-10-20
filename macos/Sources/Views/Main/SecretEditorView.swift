import SwiftUI

struct EditorRequest: Identifiable {
    let id = UUID()
    /// nil means "add a new variable".
    let secret: FfiSecret?
    /// For a new variable: start with this key (overriding an inherited variable).
    var prefillKey: String? = nil
    var prefillSecret = true
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
    @State private var expires = false
    @State private var expiryDate = Calendar.current.date(byAdding: .day, value: 90, to: Date()) ?? Date()
    @State private var originalExpiry: Int64?
    @State private var valueType: String?
    @State private var originalType: String?
    @State private var typeTouched = false

    private static let types: [(tag: String, label: String)] = [
        ("", "Text"), ("url", "URL"), ("number", "Number"), ("port", "Port"),
        ("boolean", "Boolean"), ("email", "Email"), ("json", "JSON"),
    ]

    /// Why the value doesn't fit the chosen type, if it doesn't.
    private var typeProblem: String? {
        valueType.flatMap { valueTypeProblem(valueType: $0, value: value) }
    }

    private var existing: FfiSecret? { request.secret }

    var body: some View {
        VStack(alignment: .leading, spacing: Layout.sheetSpacing) {
            Text(existing == nil ? "Add Variable" : "Edit Variable")
                .font(.title3.bold())

            VStack(alignment: .leading, spacing: 4) {
                Text("Key").font(.caption).foregroundStyle(.secondary)
                TextField("API_KEY", text: $key)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
                    .onChange(of: key) { _, new in
                        if existing == nil && !kindTouched { isSecret = looksSecret(key: new) }
                        if existing == nil && !typeTouched { valueType = suggestValueType(key: new) }
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
                if let typeProblem {
                    Text("This value isn't valid: \(typeProblem)").font(.caption).foregroundStyle(.red)
                }
            }

            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Type")
                    Text("Values are checked against it whenever they change.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Picker("Type", selection: Binding(get: { valueType ?? "" }, set: { valueType = $0.isEmpty ? nil : $0; typeTouched = true })) {
                    ForEach(Self.types, id: \.tag) { Text($0.label).tag($0.tag) }
                }
                .labelsHidden()
                .fixedSize()
            }

            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Secret")
                    Text(isSecret
                         ? "Value is masked until you reveal it."
                         : "Plain variable — value is shown in the list.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Toggle("Secret", isOn: Binding(get: { isSecret }, set: { isSecret = $0; kindTouched = true }))
                    .toggleStyle(.switch)
                    .labelsHidden()
            }

            HStack {
                Toggle("Expires", isOn: $expires)
                if expires {
                    DatePicker("", selection: $expiryDate, in: Date()..., displayedComponents: .date)
                        .labelsHidden()
                    Text("You'll get a reminder a week before.").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }

            SheetError(text: error)

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(existing == nil ? "Add" : "Save", action: save)
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(!isValidKey(key: key) || typeProblem != nil)
            }
        }
        .padding(20)
        .frame(width: Layout.sheetMedium)
        .onAppear(perform: prefill)
    }

    private func prefill() {
        if existing == nil, let k = request.prefillKey {
            key = k
            isSecret = request.prefillSecret
            kindTouched = true
        }
        guard let s = existing else { return }
        key = s.key
        valueType = s.valueType
        originalType = s.valueType
        isSecret = s.isSecret
        originalExpiry = s.expiresAt
        if let exp = s.expiresAt {
            expires = true
            expiryDate = Date(timeIntervalSince1970: TimeInterval(exp))
        }
        do {
            let current = try session.getSecretPlaintext(projectId: projectId, secretId: s.id)
            value = current
            originalValue = current
        } catch {
            self.error = "Couldn't read the current value: \(userMessage(error))"
        }
    }

    private func save() {
        let ok: Bool
        let newExpiry: Int64? = expires ? Int64(expiryDate.timeIntervalSince1970) : nil
        let typeChanged = valueType != originalType
        if let s = existing {
            // Clear the old type first so a new value is checked against the new type only.
            ok = (!typeChanged || originalType == nil || vm.setValueType(projectId: projectId, secretId: s.id, valueType: nil, session: session))
                && vm.editSecret(projectId: projectId, secret: s, newKey: key,
                                 newValue: value == originalValue ? nil : value,
                                 isSecret: isSecret, session: session)
                && (newExpiry == originalExpiry || vm.setExpiry(projectId: projectId, secret: s, expiresAt: newExpiry, session: session))
                && (!typeChanged || valueType == nil || vm.setValueType(projectId: projectId, secretId: s.id, valueType: valueType, session: session))
        } else {
            ok = vm.createSecret(projectId: projectId, envId: envId, key: key, value: value,
                                 isSecret: isSecret, expiresAt: newExpiry, session: session)
                && (valueType == nil || vm.secrets.first(where: { $0.key == key }).map {
                    vm.setValueType(projectId: projectId, secretId: $0.id, valueType: valueType, session: session)
                } ?? true)
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

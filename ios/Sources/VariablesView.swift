import SwiftUI

/// Read-only list of an environment's variables, own and inherited.
struct VariablesView: View {
    let session: YasecretSession
    let projectId: String
    let env: FfiEnvironment
    @Environment(MobileState.self) private var state
    @State private var own: [FfiSecret] = []
    @State private var inherited: [FfiInheritedVar] = []
    @State private var revealed: [String: String] = [:]
    @State private var search = ""
    @State private var copied: String?

    var body: some View {
        List {
            Section {
                ForEach(own.filter(matches), id: \.id) { s in
                    row(id: s.id, key: s.key, isSecret: s.isSecret, plain: nil, note: s.valueType)
                }
            }
            if !inherited.isEmpty {
                Section("Inherited") {
                    ForEach(inherited.filter { matchesKey($0.key) }, id: \.key) { v in
                        row(id: v.secretId, key: v.key, isSecret: v.isSecret, plain: v.value, note: "from \(v.fromEnv)")
                    }
                }
            }
        }
        .searchable(text: $search)
        .navigationTitle(env.name)
        .onAppear(perform: load)
        .onChange(of: state.revision) { _, _ in load() }
        .refreshable { load() }
    }

    private func matches(_ s: FfiSecret) -> Bool { matchesKey(s.key) }
    private func matchesKey(_ k: String) -> Bool { search.isEmpty || k.localizedCaseInsensitiveContains(search) }

    private func row(id: String, key: String, isSecret: Bool, plain: String?, note: String?) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Image(systemName: isSecret ? "lock.fill" : "textformat").font(.caption).foregroundStyle(isSecret ? .orange : .secondary)
                Text(key).font(.system(.body, design: .monospaced))
                if let note { Text(note).font(.caption2).foregroundStyle(.secondary) }
                Spacer()
                if copied == id { Image(systemName: "checkmark").foregroundStyle(.green) }
            }
            Text(displayValue(id: id, isSecret: isSecret, plain: plain))
                .font(.system(.callout, design: .monospaced))
                .foregroundStyle(.secondary)
                .lineLimit(3)
        }
        .contentShape(Rectangle())
        .onTapGesture { if isSecret { toggleReveal(id) } }
        .swipeActions {
            Button("Copy") { copy(id: id, isSecret: isSecret, plain: plain) }.tint(.blue)
        }
        .contextMenu {
            Button("Copy Value", systemImage: "doc.on.doc") { copy(id: id, isSecret: isSecret, plain: plain) }
            Button("Copy Name", systemImage: "textformat") { copyToClipboard(key, sensitive: false) }
            if isSecret {
                Button(revealed[id] == nil ? "Reveal" : "Hide", systemImage: "eye") { toggleReveal(id) }
            }
        }
    }

    private func displayValue(id: String, isSecret: Bool, plain: String?) -> String {
        if isSecret { return revealed[id] ?? "••••••••••••  tap to reveal" }
        return plain ?? revealed[id] ?? (try? session.getSecretPlaintext(projectId: projectId, secretId: id)) ?? ""
    }

    private func value(id: String, plain: String?) -> String? {
        plain ?? revealed[id] ?? (try? session.getSecretPlaintext(projectId: projectId, secretId: id))
    }

    private func toggleReveal(_ id: String) {
        if revealed[id] != nil {
            revealed[id] = nil
        } else if let v = try? session.getSecretPlaintext(projectId: projectId, secretId: id) {
            try? session.recordReveal(secretId: id)
            revealed[id] = v
        }
    }

    private func copy(id: String, isSecret: Bool, plain: String?) {
        guard let v = value(id: id, plain: plain) else { return }
        copyToClipboard(v, sensitive: isSecret)
        copied = id
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { if copied == id { copied = nil } }
    }

    private func load() {
        own = (try? session.listSecrets(envId: env.id)) ?? []
        inherited = (try? session.listInherited(envId: env.id)) ?? []
    }
}

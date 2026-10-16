import SwiftUI

struct HistorySheet: View {
    let secret: FfiSecret
    let projectId: String
    let session: YasecretSession
    var readOnly = false
    var onRestored: () -> Void = {}
    @Environment(\.dismiss) private var dismiss

    @State private var versions: [FfiVersion] = []
    @State private var current = ""
    @State private var revealed: Set<String> = []
    @State private var pendingRestore: FfiVersion?
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 2) {
                Text("History").font(.title3.bold())
                Text(secret.key).font(.system(.callout, design: .monospaced)).foregroundStyle(.secondary)
            }

            List {
                Section("Current") {
                    row(id: "current", value: current, date: secret.updatedAt, by: nil, note: nil, restorable: nil)
                }
                Section(versions.isEmpty ? "No earlier values" : "Earlier values") {
                    ForEach(versions, id: \.id) { v in
                        row(id: v.id, value: v.value, date: v.changedAt, by: v.byMe ? "you" : "a teammate",
                            note: v.note, restorable: v)
                    }
                }
            }
            .frame(minHeight: 260)

            if let error {
                Text(error).font(.callout).foregroundStyle(.red)
            }
            HStack {
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 560, height: 460)
        .onAppear(perform: load)
        .confirmationDialog("Restore this value?", isPresented: Binding(get: { pendingRestore != nil }, set: { if !$0 { pendingRestore = nil } }), titleVisibility: .visible) {
            Button("Restore") { restore() }
        } message: {
            Text("The current value is kept in history, so you can undo this.")
        }
    }

    private func row(id: String, value: String, date: Int64, by: String?, note: String?, restorable: FfiVersion?) -> some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 3) {
                Text(secret.isSecret && !revealed.contains(id) ? "••••••••••••" : (value.isEmpty ? "(empty)" : value))
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(2)
                    .textSelection(.enabled)
                Text(caption(date: date, by: by, note: note))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if secret.isSecret {
                Button { toggle(id) } label: {
                    Image(systemName: revealed.contains(id) ? "eye.slash" : "eye")
                }
                .buttonStyle(.borderless)
            }
            if let v = restorable, !readOnly {
                Button("Restore") { pendingRestore = v }
            }
        }
    }

    private func caption(date: Int64, by: String?, note: String?) -> String {
        let when = Date(timeIntervalSince1970: TimeInterval(date)).formatted(date: .abbreviated, time: .shortened)
        var parts = [by.map { "Replaced \(when) by \($0)" } ?? "Set \(when)"]
        if let note, note != "" { parts.append(note) }
        return parts.joined(separator: " · ")
    }

    private func toggle(_ id: String) {
        if revealed.contains(id) {
            revealed.remove(id)
        } else {
            revealed.insert(id)
            try? session.recordReveal(secretId: secret.id)
        }
    }

    private func load() {
        do {
            current = try session.getSecretPlaintext(projectId: projectId, secretId: secret.id)
            versions = try session.listVersions(projectId: projectId, secretId: secret.id)
        } catch {
            self.error = userMessage(error)
        }
    }

    private func restore() {
        guard let v = pendingRestore else { return }
        pendingRestore = nil
        do {
            try session.restoreVersion(projectId: projectId, secretId: secret.id, versionId: v.id)
            onRestored()
            load()
        } catch {
            self.error = userMessage(error)
        }
    }
}

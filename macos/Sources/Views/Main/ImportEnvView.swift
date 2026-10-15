import SwiftUI
import AppKit

struct ImportEnvView: View {
    let projectId: String
    let envId: String
    let session: YasecretSession
    let onComplete: (Int) -> Void
    @Environment(\.dismiss) private var dismiss

    @State private var content = ""
    @State private var errorMsg: String?
    @State private var importing = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Import .env")
                .font(.headline)

            Text("Paste the contents of a .env file below, or click Browse to open one.")
                .foregroundStyle(.secondary)
                .font(.callout)

            TextEditor(text: $content)
                .font(.system(.body, design: .monospaced))
                .frame(height: 200)
                .border(Color.secondary.opacity(0.4))

            if let err = errorMsg {
                Text(err).foregroundStyle(.red).font(.caption)
            }

            HStack {
                Button("Browse…") {
                    let panel = NSOpenPanel()
                    panel.canChooseFiles = true
                    panel.canChooseDirectories = false
                    if panel.runModal() == .OK, let url = panel.url {
                        content = (try? String(contentsOf: url)) ?? ""
                    }
                }
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Import") {
                    importing = true
                    errorMsg = nil
                    do {
                        let count = try session.importEnv(
                            projectId: projectId, envId: envId, content: content)
                        onComplete(Int(count))
                        dismiss()
                    } catch {
                        errorMsg = error.localizedDescription
                    }
                    importing = false
                }
                .buttonStyle(.borderedProminent)
                .disabled(content.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || importing)
            }
        }
        .padding(24)
        .frame(width: 480)
    }
}

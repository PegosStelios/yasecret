import SwiftUI
import AppKit

struct SecretRowView: View {
    let secret: FfiSecret
    let projectId: String
    let session: YasecretSession

    @State private var isRevealed = false
    @State private var revealedValue: String?
    @State private var isCopied = false

    var body: some View {
        HStack {
            Text(secret.key)
                .font(.system(.body, design: .monospaced))
                .frame(maxWidth: .infinity, alignment: .leading)

            if isRevealed, let val = revealedValue {
                Text(val)
                    .font(.system(.body, design: .monospaced))
                    .frame(width: 200, alignment: .leading)
                    .lineLimit(1)
                    .truncationMode(.tail)
            } else {
                Text("••••••••")
                    .foregroundStyle(.secondary)
                    .frame(width: 200, alignment: .leading)
            }

            Button {
                if isRevealed {
                    isRevealed = false
                    revealedValue = nil
                } else {
                    revealedValue = try? session.getSecretPlaintext(
                        projectId: projectId, secretId: secret.id)
                    isRevealed = revealedValue != nil
                }
            } label: {
                Image(systemName: isRevealed ? "eye.slash" : "eye")
            }
            .buttonStyle(.borderless)
            .help(isRevealed ? "Hide value" : "Show value")

            Button {
                let val = revealedValue ?? (try? session.getSecretPlaintext(
                    projectId: projectId, secretId: secret.id))
                if let val {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(val, forType: .string)
                    isCopied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { isCopied = false }
                }
            } label: {
                Image(systemName: isCopied ? "checkmark" : "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .help("Copy to clipboard")
        }
        .padding(.vertical, 2)
    }
}

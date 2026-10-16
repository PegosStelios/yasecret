import SwiftUI

struct JoinSheet: View {
    let session: YasecretSession
    @State var link: String
    let onJoined: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    @State private var joining = false
    @State private var error: String?
    @State private var deviceCode = ""
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Join a Shared Project").font(.title3.bold())
            Text("Paste the invite link you were sent. The person who shared it needs Yasecret open and unlocked while you join.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            TextEditor(text: $link)
                .font(.system(.caption, design: .monospaced))
                .scrollContentBackground(.hidden)
                .padding(6)
                .frame(height: 80)
                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(.separator))
                .disabled(joining)

            GroupBox {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Asked for a device code? Send this to the project owner:")
                        .font(.callout)
                    HStack {
                        Text(grouped(deviceCode))
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                        Spacer()
                        Button {
                            Clipboard.copy(deviceCode, sensitive: false)
                            copied = true
                            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { copied = false }
                        } label: {
                            Label(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                        }
                    }
                }
                .padding(4)
            }

            if let error {
                Text(error).font(.callout).foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                if joining {
                    ProgressView().controlSize(.small)
                    Text("Connecting to the owner's Mac…").foregroundStyle(.secondary)
                }
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Join", action: join)
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(joining || !trimmed.hasPrefix("yasecret://join"))
            }
        }
        .padding(20)
        .frame(width: 520)
        .onAppear { deviceCode = (try? session.deviceCode()) ?? "" }
    }

    private var trimmed: String { link.trimmingCharacters(in: .whitespacesAndNewlines) }

    private func grouped(_ code: String) -> String {
        stride(from: 0, to: code.count, by: 8).map { i -> String in
            let start = code.index(code.startIndex, offsetBy: i)
            let end = code.index(start, offsetBy: min(8, code.count - i))
            return String(code[start..<end])
        }.joined(separator: " ")
    }

    private func join() {
        joining = true
        error = nil
        let (session, url) = (session, trimmed)
        Task.detached {
            do {
                let projectId = try session.joinProject(link: url)
                await MainActor.run {
                    joining = false
                    onJoined(projectId)
                    dismiss()
                }
            } catch {
                let msg = userMessage(error)
                await MainActor.run { self.error = msg; joining = false }
            }
        }
    }
}

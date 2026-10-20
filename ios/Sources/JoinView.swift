import SwiftUI

struct JoinView: View {
    let session: YasecretSession
    @Environment(MobileState.self) private var state
    @Environment(\.dismiss) private var dismiss
    @State private var link = ""
    @State private var code = ""
    @State private var joining = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(code.isEmpty ? "Unavailable" : code)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                    Button("Copy Device Code", systemImage: "doc.on.doc") { copyToClipboard(code, sensitive: false) }
                        .disabled(code.isEmpty)
                    ShareLink(item: code) { Label("Send to the Owner", systemImage: "square.and.arrow.up") }
                        .disabled(code.isEmpty)
                } header: {
                    Text("This phone's device code")
                } footer: {
                    Text("The owner pastes it into a device-bound invite (ideally with “Can view”), which only this phone can use.")
                }
                Section {
                    TextField("yasecret://join?…", text: $link, axis: .vertical)
                        .font(.system(.caption, design: .monospaced))
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Button {
                        join()
                    } label: {
                        if joining { ProgressView() } else { Text("Join") }
                    }
                    .disabled(joining || !link.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("yasecret://join"))
                } header: {
                    Text("Invite link")
                } footer: {
                    Text("The owner's computer (or an always-on peer) needs to be online while you join.")
                }
                if let error { Text(error).foregroundStyle(.red) }
            }
            .navigationTitle("Join a Project")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } } }
            .interactiveDismissDisabled(joining)
        }
        .onAppear {
            code = (try? session.deviceCode()) ?? ""
            if let pending = state.pendingJoinLink {
                link = pending
                state.pendingJoinLink = nil
            }
        }
    }

    private func join() {
        joining = true
        error = nil
        let url = link.trimmingCharacters(in: .whitespacesAndNewlines)
        let session = session
        Task {
            do {
                _ = try await Task.detached { try session.joinProject(link: url) }.value
                dismiss()
            } catch {
                self.error = describe(error)
            }
            joining = false
        }
    }
}

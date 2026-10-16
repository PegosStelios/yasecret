import SwiftUI

struct ShareSheet: View {
    let projectId: String
    let projectName: String
    let session: YasecretSession
    let sharing: SharingViewModel
    var onStopped: () -> Void = {}
    @Environment(\.dismiss) private var dismiss

    enum Mode: String, CaseIterable, Identifiable {
        case link, device
        var id: String { rawValue }
        var label: String { self == .link ? "Invite link" : "Device-bound invite" }
    }

    @State private var mode: Mode = .link
    @State private var access: AccessLevel = .editor
    @State private var deviceCode = ""
    @State private var link: String?
    @State private var working = false
    @State private var error: String?
    @State private var copied = false
    @State private var confirmStop = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Share “\(projectName)”").font(.title3.bold())
                Spacer()
                if let summary = sharing.summary {
                    Text(summary).font(.callout).foregroundStyle(.secondary)
                }
            }

            if sharing.isOwner {
                inviteSection
            } else {
                Label("Only the owner of this project can invite people.", systemImage: "info.circle")
                    .foregroundStyle(.secondary)
            }

            if sharing.isShared {
                Divider()
                membersSection
            }

            if let error {
                Text(error).font(.callout).foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                if sharing.isShared {
                    Button(sharing.isOwner ? "Stop Sharing…" : "Leave Project…", role: .destructive) {
                        confirmStop = true
                    }
                }
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 560)
        .task {
            while !Task.isCancelled {
                sharing.refresh(projectId: projectId, session: session)
                try? await Task.sleep(for: .seconds(3))
            }
        }
        .confirmationDialog(
            sharing.isOwner ? "Stop sharing “\(projectName)”?" : "Leave “\(projectName)”?",
            isPresented: $confirmStop,
            titleVisibility: .visible
        ) {
            Button(sharing.isOwner ? "Stop Sharing" : "Leave and Remove", role: .destructive, action: stop)
        } message: {
            Text(sharing.isOwner
                 ? "Everyone loses access to future changes. The project key is replaced, so old invites and copies can't read new values. You keep all your data."
                 : "The project and its variables are removed from this Mac. You'll need a new invite to rejoin.")
        }
    }

    // MARK: Invite

    private var inviteSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Picker("", selection: $mode) {
                ForEach(Mode.allCases) { Text($0.label).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .onChange(of: mode) { _, _ in link = nil; error = nil }

            Text(mode == .link
                 ? "Anyone with the link can join once, within 24 hours. Send it over a private channel."
                 : "Only the device whose code you paste can use this invite, so it's safe to send anywhere. Your teammate finds their code in Join Project.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if mode == .device {
                TextField("Teammate's device code", text: $deviceCode)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
            }

            HStack {
                Picker("Access", selection: $access) {
                    ForEach(AccessLevel.allCases) { Text($0.label).tag($0) }
                }
                .frame(width: 200)
                Spacer()
                if working { ProgressView().controlSize(.small) }
                Button(link == nil ? "Create Invite" : "Create Another", action: createInvite)
                    .buttonStyle(.borderedProminent)
                    .disabled(working || (mode == .device && cleanedCode.count != 64))
            }

            if let link {
                VStack(alignment: .leading, spacing: 6) {
                    HStack(alignment: .top) {
                        Text(link)
                            .font(.system(.caption, design: .monospaced))
                            .lineLimit(3)
                            .truncationMode(.middle)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        Button {
                            Clipboard.copy(link, sensitive: mode == .link)
                            copied = true
                            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { copied = false }
                        } label: {
                            Label(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                        }
                    }
                    .padding(10)
                    .background(.quaternary.opacity(0.6), in: RoundedRectangle(cornerRadius: 8))
                    Label("Keep Yasecret open and unlocked until they've joined. Devices sync directly, with no server in between.",
                          systemImage: "antenna.radiowaves.left.and.right")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    private var cleanedCode: String {
        deviceCode.filter { !$0.isWhitespace }
    }

    // MARK: Members

    private var membersSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("People").font(.headline)
            if sharing.members.isEmpty {
                Text("No one has joined yet.").foregroundStyle(.secondary)
            }
            ForEach(sharing.members, id: \.peerId) { m in
                HStack {
                    Image(systemName: m.level == "owner" ? "crown" : "person.crop.circle")
                        .foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(m.name + (m.isMe ? " (this Mac)" : ""))
                        Text("Joined \(Date(timeIntervalSince1970: TimeInterval(m.joinedAt)), format: .relative(presentation: .named))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if sharing.isOwner && !m.isMe && m.level != "owner" && m.level != "pending" {
                        Menu(levelLabel(m.level)) {
                            Button("Can edit") { setLevel(m, "editor") }
                            Button("Can view") { setLevel(m, "viewer") }
                            Divider()
                            Button("Remove", role: .destructive) { setLevel(m, "removed") }
                        }
                        .fixedSize()
                    } else {
                        Text(levelLabel(m.level)).foregroundStyle(.secondary)
                    }
                }
            }
            if sharing.isOwner && sharing.members.count > 1 {
                Text("Removing someone stops their changes from being accepted. To also cut off reading, stop sharing and invite the others again.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    // MARK: Actions

    private func createInvite() {
        working = true
        error = nil
        let code: String? = mode == .device ? cleanedCode : nil
        let level = access.rawValue
        let (session, pid) = (session, projectId)
        Task.detached {
            do {
                let url = try session.createInvite(projectId: pid, deviceCode: code, level: level)
                await MainActor.run { link = url; working = false }
            } catch {
                let msg = userMessage(error)
                await MainActor.run { self.error = msg; working = false }
            }
        }
    }

    private func setLevel(_ m: FfiMember, _ level: String) {
        do {
            try session.setMemberLevel(projectId: projectId, peerId: m.peerId, level: level)
            sharing.refresh(projectId: projectId, session: session)
        } catch {
            self.error = userMessage(error)
        }
    }

    private func stop() {
        do {
            try session.stopSharing(projectId: projectId)
            sharing.refresh(projectId: projectId, session: session)
            onStopped()
            dismiss()
        } catch {
            self.error = userMessage(error)
        }
    }
}

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
    @State private var pendingRemoval: FfiMember?
    @State private var relayCode = ""
    @State private var relayName = ""
    @State private var relayCommand: String?
    @State private var relayCopied = false

    /// Return creates the invite while one can be made; otherwise it closes the sheet.
    private var inviteIsDefault: Bool { sharing.isOwner && link == nil && relayCode.isEmpty }
    private var cleanedRelayCode: String { relayCode.filter { !$0.isWhitespace }.lowercased() }

    var body: some View {
        VStack(alignment: .leading, spacing: Layout.sheetSpacing) {
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

            if sharing.isOwner || !sharing.relays.isEmpty {
                Divider()
                relaySection
            }

            SheetError(text: error)

            HStack {
                if sharing.isShared {
                    Button(sharing.isOwner ? "Stop Sharing…" : "Leave Project…", role: .destructive) {
                        confirmStop = true
                    }
                }
                Spacer()
                if inviteIsDefault {
                    Button("Done") { dismiss() }
                        .keyboardShortcut(.cancelAction)
                } else {
                    Button("Done") { dismiss() }
                        .keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(20)
        .frame(width: Layout.sheetLarge)
        .task {
            if DevHook.open == "share-invite" {
                // Sync starts in the background after unlock; retry until it's up.
                for _ in 0..<20 where link == nil {
                    try? await Task.sleep(for: .seconds(1))
                    if let url = try? session.createInvite(projectId: projectId, deviceCode: nil, level: "editor") {
                        link = url
                    }
                }
            }
        }
        .task {
            while !Task.isCancelled {
                await sharing.refresh(projectId: projectId, session: session)
                try? await Task.sleep(for: .seconds(3))
            }
        }
        .confirmationDialog(
            "Remove \(pendingRemoval?.name ?? "")?",
            isPresented: Binding(get: { pendingRemoval != nil }, set: { if !$0 { pendingRemoval = nil } }),
            titleVisibility: .visible
        ) {
            Button("Remove", role: .destructive) {
                if let m = pendingRemoval { setLevel(m, "removed") }
                pendingRemoval = nil
            }
        } message: {
            Text("The project key is replaced and handed to everyone else, so they can't read anything changed afterwards.")
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
                 : "Only the device whose code you paste can use this invite, so it's safe to send anywhere. Your teammate finds their code under Join Shared Project.")
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
                if inviteIsDefault {
                    Button("Create Invite", action: createInvite)
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.defaultAction)
                        .disabled(working || (mode == .device && cleanedCode.count != 64))
                } else {
                    Button("Create Another", action: createInvite)
                        .disabled(working || (mode == .device && cleanedCode.count != 64))
                }
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
                            Button("Remove…", role: .destructive) { pendingRemoval = m }
                        }
                        .fixedSize()
                    } else {
                        Text(levelLabel(m.level)).foregroundStyle(.secondary)
                    }
                }
            }
            if sharing.isOwner && sharing.members.count > 1 {
                Text("Removing someone replaces the project key, so they can't read anything changed afterwards.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    // MARK: Always-on peer

    private var relaySection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Always-on peer").font(.headline)
            Text("Run `yasecret relay` on a computer that stays on, so teammates can join and sync while this Mac is off. It only stores encrypted values.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(sharing.relays, id: \.code) { r in
                HStack {
                    Image(systemName: "server.rack").foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(r.name)
                        Text(r.code.prefix(16) + "…")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Label(r.online ? "Online" : "Offline", systemImage: "circle.fill")
                        .font(.caption)
                        .foregroundStyle(r.online ? .green : .secondary)
                    if sharing.isOwner {
                        Button("Remove") {
                            run { session, pid in try session.removeRelay(projectId: pid, code: r.code) } done: {}
                        }
                    }
                }
            }
            if sharing.isOwner {
                HStack {
                    TextField("Relay code (yasecret relay code)", text: $relayCode)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.body, design: .monospaced))
                    TextField("Name (optional)", text: $relayName)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 140)
                    if relayCode.isEmpty {
                        Button("Add", action: addRelay).disabled(true)
                    } else {
                        Button("Add", action: addRelay)
                            .keyboardShortcut(.defaultAction)
                            .disabled(working || cleanedRelayCode.count != 64)
                    }
                }
            }
            if let relayCommand {
                Text("Run this on the relay machine:").font(.caption).foregroundStyle(.secondary)
                HStack(alignment: .top) {
                    Text(relayCommand)
                        .font(.system(.caption, design: .monospaced))
                        .lineLimit(3)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Button {
                        Clipboard.copy(relayCommand, sensitive: true)
                        relayCopied = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { relayCopied = false }
                    } label: {
                        Label(relayCopied ? "Copied" : "Copy", systemImage: relayCopied ? "checkmark" : "doc.on.doc")
                    }
                }
                .padding(10)
                .background(.quaternary.opacity(0.6), in: RoundedRectangle(cornerRadius: 8))
            }
        }
    }

    private func addRelay() {
        working = true
        error = nil
        let (session, pid, code, name) = (session, projectId, cleanedRelayCode, relayName)
        Task {
            let result = await Task.detached { () -> Result<String, Error> in
                Result { try session.addRelay(projectId: pid, code: code, name: name) }
            }.value
            working = false
            switch result {
            case .success(let link):
                relayCommand = "yasecret relay add '\(link)'"
                relayCode = ""
                relayName = ""
                await sharing.refresh(projectId: pid, session: session)
            case .failure(let failure):
                error = userMessage(failure)
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
        run { session, pid in try session.setMemberLevel(projectId: pid, peerId: m.peerId, level: level) } done: {}
    }

    private func stop() {
        run { session, pid in try session.stopSharing(projectId: pid) } done: {
            onStopped()
            dismiss()
        }
    }

    /// Network-bound sharing calls run off the main thread; errors land in the sheet.
    private func run(_ work: @escaping @Sendable (YasecretSession, String) throws -> Void, done: @escaping () -> Void) {
        working = true
        error = nil
        let (session, pid) = (session, projectId)
        Task {
            let failure = await Task.detached { () -> String? in
                do { try work(session, pid); return nil } catch { return userMessage(error) }
            }.value
            working = false
            if let failure {
                error = failure
            } else {
                await sharing.refresh(projectId: pid, session: session)
                done()
            }
        }
    }
}

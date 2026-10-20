import Foundation

@MainActor
@Observable
final class SharingViewModel {
    var status: FfiSyncStatus?
    var members: [FfiMember] = []
    var relays: [FfiRelay] = []

    var isShared: Bool { status?.shared == true }
    /// Owner or co-owner: can invite people and change access.
    var isOwner: Bool { !isShared || status?.isOwner == true }
    /// The owner who shared the project: can appoint co-owners and stop sharing.
    var isRoot: Bool { !isShared || status?.isRoot == true }

    /// Co-owners manage everyone except owners; only the root owner manages co-owners.
    func canManage(_ m: FfiMember) -> Bool {
        isOwner && !m.isMe && !m.isRoot && m.level != "pending" && (m.level != "owner" || isRoot)
    }

    func accessLabel(_ m: FfiMember) -> String {
        m.level == "owner" ? (m.isRoot ? "Owner" : "Co-owner") : levelLabel(m.level)
    }
    /// Anyone who isn't an owner or editor can't change shared data: their edits would never sync.
    var isReadOnly: Bool { isShared && !["owner", "editor"].contains(status?.myLevel ?? "") }

    var error: String?
    private var requestId = UUID()

    /// Reads status and members off the main thread; only the latest request may update state.
    func refresh(projectId: String, session: YasecretSession) async {
        let id = UUID()
        requestId = id
        let (st, list, relayList, err) = await Task.detached { () -> (FfiSyncStatus?, [FfiMember], [FfiRelay], String?) in
            do {
                let st = try session.syncStatus(projectId: projectId)
                let list = st.shared ? try session.listMembers(projectId: projectId) : []
                let relayList = st.shared ? try session.listRelays(projectId: projectId) : []
                return (st, list, relayList, nil)
            } catch {
                return (nil, [], [], userMessage(error))
            }
        }.value
        guard requestId == id else { return }
        status = st
        members = list
        relays = relayList
        error = err
    }

    func clear() {
        requestId = UUID()
        status = nil
        members = []
        relays = []
        error = nil
    }

    var summary: String? {
        guard let s = status, s.shared else { return nil }
        var parts: [String] = []
        switch s.myLevel {
        case "viewer": parts.append("View only")
        case "pending": parts.append("Waiting for owner")
        default: parts.append("Shared")
        }
        let others = max(members.count - 1, 0)
        if others == 0 {
            parts.append(s.isOwner ? "no one has joined" : "connecting")
        } else {
            parts.append(plural(others, "member"))
            parts.append(s.peersOnline > 0 ? "\(s.peersOnline) online" : "none online")
        }
        return parts.joined(separator: " · ")
    }
}

enum AccessLevel: String, CaseIterable, Identifiable {
    case editor, viewer
    var id: String { rawValue }
    var label: String { self == .editor ? "Can edit" : "Can view" }
}

func levelLabel(_ level: String) -> String {
    switch level {
    case "owner": return "Owner"
    case "editor": return "Can edit"
    case "viewer": return "Can view"
    case "pending": return "Waiting for owner"
    default: return level.capitalized
    }
}

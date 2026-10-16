import Foundation

@MainActor
@Observable
final class SharingViewModel {
    var status: FfiSyncStatus?
    var members: [FfiMember] = []

    var isShared: Bool { status?.shared == true }
    var isOwner: Bool { !isShared || status?.isOwner == true }
    /// Anyone who isn't an owner or editor can't change shared data: their edits would never sync.
    var isReadOnly: Bool { isShared && !["owner", "editor"].contains(status?.myLevel ?? "") }

    func refresh(projectId: String, session: YasecretSession) {
        status = try? session.syncStatus(projectId: projectId)
        members = isShared ? ((try? session.listMembers(projectId: projectId)) ?? []) : []
    }

    func clear() {
        status = nil
        members = []
    }

    var summary: String? {
        guard let s = status, s.shared else { return nil }
        var parts: [String] = []
        switch s.myLevel {
        case "owner": parts.append("Shared by you")
        case "viewer": parts.append("View only")
        case "pending": parts.append("Waiting for the owner")
        default: parts.append("Shared")
        }
        let others = max(members.count - 1, 0)
        if others > 0 { parts.append("\(others) member\(others == 1 ? "" : "s")") }
        parts.append(s.peersOnline > 0 ? "\(s.peersOnline) online" : "offline")
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
    case "pending": return "Joining…"
    default: return level.capitalized
    }
}

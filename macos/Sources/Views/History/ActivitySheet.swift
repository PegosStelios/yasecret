import SwiftUI

struct ActivitySheet: View {
    let projectId: String
    let projectName: String
    let session: YasecretSession
    @Environment(\.dismiss) private var dismiss

    @State private var entries: [FfiActivity] = []
    @State private var filter = ""
    @State private var loadError: String?

    private var shown: [FfiActivity] {
        let q = filter.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return entries }
        return entries.filter { $0.targetLabel.localizedCaseInsensitiveContains(q) || describe($0.action).localizedCaseInsensitiveContains(q) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Layout.sheetSpacing) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Activity").font(.title3.bold())
                    Text("\(projectName) · kept on this Mac only").font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                TextField("Filter", text: $filter)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 180)
            }
            if let loadError {
                ContentUnavailableView("Couldn't load activity", systemImage: "exclamationmark.triangle",
                                       description: Text(loadError))
                    .frame(maxHeight: .infinity)
            } else if entries.isEmpty {
                ContentUnavailableView("No activity yet", systemImage: "clock.arrow.circlepath")
                    .frame(maxHeight: .infinity)
            } else if shown.isEmpty {
                ContentUnavailableView.search(text: filter)
                    .frame(maxHeight: .infinity)
            } else {
                Table(shown) {
                    TableColumn("When") { a in
                        Text(Date(timeIntervalSince1970: TimeInterval(a.timestamp)).formatted(date: .abbreviated, time: .shortened))
                            .foregroundStyle(.secondary)
                    }
                    .width(min: 130, ideal: 145, max: 160)
                    TableColumn("What") { a in
                        Label(describe(a.action), systemImage: icon(a.action))
                    }
                    .width(min: 110, ideal: 130, max: 150)
                    TableColumn("Variable") { a in
                        Text(a.targetLabel)
                            .font(.system(.body, design: .monospaced))
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .help(a.targetLabel)
                    }
                    .width(min: 200, ideal: 270)
                    TableColumn("Who") { a in
                        Text(a.device ?? (a.fromSync ? "Teammate (synced)" : (a.byMe ? "You" : "Teammate")))
                            .foregroundStyle(.secondary)
                    }
                    .width(min: 70, ideal: 90, max: 120)
                }
                .alternatingRowBackgrounds(.disabled)
            }
            HStack {
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: Layout.sheetWide, height: 520)
        .onAppear {
            do {
                entries = try session.listActivity(projectId: projectId, limit: 500)
            } catch {
                loadError = userMessage(error)
            }
        }
    }

    private func describe(_ action: String) -> String {
        switch action {
        case "created_secret": return "Added"
        case "updated_secret": return "Changed value"
        case "deleted_secret": return "Deleted"
        case "renamed_secret": return "Renamed"
        case "changed_kind": return "Changed type"
        case "changed_expiry": return "Changed expiry"
        case "revealed_secret": return "Revealed"
        case "synced_secret": return "Synced change"
        default: return action.replacingOccurrences(of: "_", with: " ").capitalized
        }
    }

    private func icon(_ action: String) -> String {
        switch action {
        case "created_secret": return "plus.circle"
        case "updated_secret": return "pencil"
        case "deleted_secret": return "trash"
        case "renamed_secret": return "character.cursor.ibeam"
        case "changed_kind": return "lock.rotation"
        case "changed_expiry": return "calendar"
        case "revealed_secret": return "eye"
        case "synced_secret": return "arrow.triangle.2.circlepath"
        default: return "circle"
        }
    }
}

extension FfiActivity: Identifiable {}

import SwiftUI

struct ActivitySheet: View {
    let projectId: String
    let projectName: String
    let session: YasecretSession
    @Environment(\.dismiss) private var dismiss

    @State private var entries: [FfiActivity] = []
    @State private var filter = ""

    private var shown: [FfiActivity] {
        let q = filter.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return entries }
        return entries.filter { $0.targetLabel.localizedCaseInsensitiveContains(q) || describe($0.action).localizedCaseInsensitiveContains(q) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
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
            if shown.isEmpty {
                ContentUnavailableView("No activity yet", systemImage: "clock")
                    .frame(maxHeight: .infinity)
            } else {
                Table(shown) {
                    TableColumn("When") { a in
                        Text(Date(timeIntervalSince1970: TimeInterval(a.timestamp)).formatted(date: .abbreviated, time: .shortened))
                            .foregroundStyle(.secondary)
                    }
                    .width(min: 120, ideal: 140)
                    TableColumn("What") { a in
                        Label(describe(a.action), systemImage: icon(a.action))
                    }
                    .width(min: 120, ideal: 150)
                    TableColumn("Variable") { a in
                        Text(a.targetLabel).font(.system(.body, design: .monospaced))
                    }
                    TableColumn("Who") { a in
                        Text(a.fromSync ? "Teammate (synced)" : (a.byMe ? "You" : "Teammate"))
                            .foregroundStyle(.secondary)
                    }
                    .width(min: 80, ideal: 120)
                }
            }
            HStack {
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 720, height: 480)
        .onAppear {
            entries = (try? session.listActivity(projectId: projectId, limit: 500)) ?? []
        }
    }

    private func describe(_ action: String) -> String {
        switch action {
        case "created_secret": return "Added"
        case "updated_secret": return "Changed value"
        case "deleted_secret": return "Deleted"
        case "renamed_secret": return "Renamed"
        case "changed_kind": return "Changed type"
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
        case "revealed_secret": return "eye"
        case "synced_secret": return "arrow.triangle.2.circlepath"
        default: return "circle"
        }
    }
}

extension FfiActivity: Identifiable {}

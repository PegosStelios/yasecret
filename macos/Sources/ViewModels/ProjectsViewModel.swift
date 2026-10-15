import Foundation

@Observable
final class ProjectsViewModel {
    var projects: [FfiProject] = []
    var selectedProjectId: String?
    var errorMessage: String?

    func load(session: YasecretSession) {
        do {
            projects = try session.listProjects()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func createProject(name: String, session: YasecretSession) {
        do {
            let p = try session.createProject(name: name, description: nil)
            projects.append(p)
            selectedProjectId = p.id
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func renameProject(id: String, newName: String, session: YasecretSession) {
        do {
            try session.renameProject(projectId: id, newName: newName)
            if let idx = projects.firstIndex(where: { $0.id == id }) {
                projects[idx] = FfiProject(id: projects[idx].id, name: newName, description: projects[idx].description)
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func deleteProject(id: String, session: YasecretSession) {
        do {
            try session.deleteProject(projectId: id)
            projects.removeAll { $0.id == id }
            if selectedProjectId == id { selectedProjectId = nil }
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

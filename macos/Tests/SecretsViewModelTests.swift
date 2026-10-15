import XCTest
@testable import Yasecret

final class SecretsViewModelTests: XCTestCase {

    private func makeSession() throws -> (YasecretSession, String, String) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let session = try YasecretSession(
            dbPath: dir.appendingPathComponent("db.sqlite").path,
            password: "pw"
        )
        let proj = try session.createProject(name: "app", description: nil)
        let env = try session.createEnvironment(projectId: proj.id, name: "dev")
        return (session, proj.id, env.id)
    }

    func testCreateSecretAppearsInList() throws {
        let (session, projId, envId) = try makeSession()
        let vm = SecretsViewModel()
        let _ = try session.createSecret(
            projectId: projId, envId: envId, key: "MY_KEY", value: "val", expiresAt: nil, isSecret: true)
        vm.load(envId: envId, session: session)
        XCTAssertEqual(vm.secrets.count, 1)
        XCTAssertEqual(vm.secrets[0].key, "MY_KEY")
    }

    func testGetPlaintextReturnsValue() throws {
        let (session, projId, envId) = try makeSession()
        let secret = try session.createSecret(
            projectId: projId, envId: envId, key: "PW", value: "secret!", expiresAt: nil, isSecret: true)
        let val = try session.getSecretPlaintext(projectId: projId, secretId: secret.id)
        XCTAssertEqual(val, "secret!")
    }

    func testDeleteSecretRemovedFromList() throws {
        let (session, projId, envId) = try makeSession()
        let secret = try session.createSecret(
            projectId: projId, envId: envId, key: "DEL", value: "bye", expiresAt: nil, isSecret: true)
        let vm = SecretsViewModel()
        vm.load(envId: envId, session: session)
        XCTAssertEqual(vm.secrets.count, 1)
        vm.deleteSecret(id: secret.id, session: session)
        XCTAssertEqual(vm.secrets.count, 0)
    }

    func testUpdateSecretChangesValue() throws {
        let (session, projId, envId) = try makeSession()
        let secret = try session.createSecret(
            projectId: projId, envId: envId, key: "K", value: "old", expiresAt: nil, isSecret: true)
        try session.updateSecret(projectId: projId, secretId: secret.id, newValue: "new")
        let val = try session.getSecretPlaintext(projectId: projId, secretId: secret.id)
        XCTAssertEqual(val, "new")
    }

    func testEditSecretRenamesAndMakesPlain() throws {
        let (session, projId, envId) = try makeSession()
        let vm = SecretsViewModel()
        XCTAssertTrue(vm.createSecret(projectId: projId, envId: envId, key: "OLD", value: "v1", session: session))
        let created = vm.secrets[0]
        XCTAssertTrue(created.isSecret)

        XCTAssertTrue(vm.editSecret(projectId: projId, secret: created, newKey: "NEW", newValue: "v2",
                                    isSecret: false, session: session))
        XCTAssertEqual(vm.secrets[0].key, "NEW")
        XCTAssertFalse(vm.secrets[0].isSecret)
        XCTAssertEqual(try session.getSecretPlaintext(projectId: projId, secretId: created.id), "v2")
    }

    func testDuplicateKeyShowsReadableError() throws {
        let (session, projId, envId) = try makeSession()
        let vm = SecretsViewModel()
        XCTAssertTrue(vm.createSecret(projectId: projId, envId: envId, key: "A", value: "1", session: session))
        XCTAssertFalse(vm.createSecret(projectId: projId, envId: envId, key: "A", value: "2", session: session))
        XCTAssertEqual(vm.errorMessage, "A variable with this name already exists in this environment")
    }

    func testSearchFiltersByKey() throws {
        let (session, projId, envId) = try makeSession()
        let vm = SecretsViewModel()
        vm.createSecret(projectId: projId, envId: envId, key: "STRIPE_KEY", value: "1", session: session)
        vm.createSecret(projectId: projId, envId: envId, key: "PORT", value: "2", isSecret: false, session: session)
        vm.searchText = "stripe"
        XCTAssertEqual(vm.filtered.map(\.key), ["STRIPE_KEY"])
    }
}

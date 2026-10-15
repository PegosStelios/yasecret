import XCTest
@testable import Yasecret

final class ImportExportTests: XCTestCase {

    private func makeSession() throws -> (YasecretSession, String, String) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let session = try YasecretSession(
            dbPath: dir.appendingPathComponent("db.sqlite").path, password: "pw")
        let proj = try session.createProject(name: "app", description: nil)
        let env = try session.createEnvironment(projectId: proj.id, name: "dev")
        return (session, proj.id, env.id)
    }

    func testImportEnvCreatesSecrets() throws {
        let (session, projId, envId) = try makeSession()
        let count = try session.importEnv(
            projectId: projId, envId: envId, content: "FOO=bar\nBAZ=qux\n")
        XCTAssertEqual(count, 2)
        let secrets = try session.listSecrets(envId: envId)
        XCTAssertEqual(secrets.count, 2)
        let keys = secrets.map(\.key)
        XCTAssertTrue(keys.contains("FOO"))
        XCTAssertTrue(keys.contains("BAZ"))
    }

    func testExportEnvContainsPlaintext() throws {
        let (session, projId, envId) = try makeSession()
        let _ = try session.createSecret(
            projectId: projId, envId: envId, key: "KEY1", value: "val1", expiresAt: nil)
        let exported = try session.exportEnv(projectId: projId, envId: envId)
        XCTAssertTrue(exported.contains("KEY1=val1"),
            "exported .env must contain plaintext: \(exported)")
    }

    func testImportMalformedLineThrows() throws {
        let (session, projId, envId) = try makeSession()
        XCTAssertThrowsError(
            try session.importEnv(projectId: projId, envId: envId, content: "NOEQUALS\n")
        )
    }
}

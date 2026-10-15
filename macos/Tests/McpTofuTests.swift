import XCTest
@testable import Yasecret

final class McpTofuTests: XCTestCase {

    private func makeSession() throws -> YasecretSession {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return try YasecretSession(
            dbPath: dir.appendingPathComponent("db.sqlite").path, password: "pw")
    }

    func testMcpSessionCountStartsAtZero() throws {
        let session = try makeSession()
        let count = try session.mcpSessionCount()
        XCTAssertEqual(count, 0)
    }

    func testGrantMcpAccessInsertsOneRow() throws {
        let session = try makeSession()
        try session.grantMcpAccess()
        let count = try session.mcpSessionCount()
        XCTAssertEqual(count, 1, "one row after grant")
    }

    func testGrantMcpAccessIsIdempotent() throws {
        let session = try makeSession()
        try session.grantMcpAccess()
        try session.grantMcpAccess()
        let count = try session.mcpSessionCount()
        XCTAssertEqual(count, 1, "still 1 row after second grant")
    }
}

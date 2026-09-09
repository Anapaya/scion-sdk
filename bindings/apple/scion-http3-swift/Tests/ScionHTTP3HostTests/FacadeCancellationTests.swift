// Copyright 2026 Anapaya Systems
import ScionHTTP3
import XCTest

/// Cancelling a `Task` cancels the request on the wire.
///
/// The generated Swift cannot see a cancelled task, so the facade fires a handle the stack watches.
final class FacadeCancellationTests: XCTestCase {
    private var server: TestServer!
    private var client: ScionHttp3Client!

    override func setUpWithError() throws {
        server = try TestServer.start()
        client = try facadeClientFor(server) { $0.requestTimeout = neverTimeout }
    }

    override func tearDown() async throws {
        await client.shutdown()
        server.stop()
    }

    private func assertCancelled(_ result: Result<ScionHttp3Response, any Error>) {
        guard case .failure(let error) = result else { return XCTFail("the request completed") }
        XCTAssertTrue(error is CancellationError, "expected CancellationError, got \(error)")
    }

    /// A request to `/hello` that must have come from the server, not from anywhere else.
    private func assertHelloWorks() async throws {
        let before = try await server.stats().requests["/hello"] ?? 0
        let response = try await client.execute(facadeRequest(server, "/hello"))
        XCTAssertEqual(response.code, 200)
        let after = try await server.stats().requests["/hello"] ?? 0
        XCTAssertEqual(after, before + 1)
    }

    func testCancellingMidBodyResetsTheStreamOnTheWireAndLeavesTheConnectionUsable() async throws {
        let tag = "facade-mid-body"
        let request = try facadeRequest(server, "/endless-body?tag=\(tag)")
        let client = self.client!
        let task = Task { try await client.execute(request) }

        try await server.waitUntil("three chunks") { ($0.endlessChunks[tag] ?? 0) >= 3 }
        let releasedBefore = try await server.stats().endlessReleased[tag] ?? 0
        XCTAssertEqual(releasedBefore, 0, "the control")

        task.cancel()
        assertCancelled(await task.result)

        try await server.waitUntil("the stream reset") { ($0.endlessReleased[tag] ?? 0) > 0 }
        try await assertHelloWorks()
    }

    func testCancellingWhileTheRequestBodyIsSentEndsTheUpload() async throws {
        // The server takes this body a chunk at a time rather than as fast as the transport
        // delivers it.
        let body = Data(repeating: 0x61, count: 2 * 1024 * 1024)
        let request = try facadeRequest(
            server, "/echo?read-interval-ms=50", method: .post, body: .bytes(body))
        let client = self.client!
        let task = Task { try await client.execute(request) }

        try await server.waitUntil("the upload to start") { ($0.uploadedBytes["/echo"] ?? 0) > 0 }
        task.cancel()
        assertCancelled(await task.result)

        try await server.waitUntil("the upload to end") { ($0.uploadsTruncated["/echo"] ?? 0) > 0 }
        try await assertHelloWorks()
    }

    func testCancellingBeforeTheResponseHeadLeavesTheConnectionUsable() async throws {
        let request = try facadeRequest(server, "/slow?ms=600000")
        let client = self.client!
        let task = Task { try await client.execute(request) }

        try await server.waitUntil("the request to reach the server") {
            ($0.started["/slow"] ?? 0) > 0
        }
        task.cancel()
        assertCancelled(await task.result)

        try await assertHelloWorks()
    }

    func testATaskCancelledBeforeTheCallSendsNothing() async throws {
        // Warm the connection first, so that "sent nothing" is not "was still connecting".
        try await assertHelloWorks()
        let before = try await server.stats().started["/hello"] ?? 0

        let request = try facadeRequest(server, "/hello")
        let client = self.client!
        let task = Task {
            // Wait until cancelled, then issue the request from a task that is already cancelled.
            while !Task.isCancelled {
                await Task.yield()
            }
            return try await client.execute(request)
        }
        task.cancel()
        assertCancelled(await task.result)

        let after = try await server.stats().started["/hello"] ?? 0
        XCTAssertEqual(after, before, "a request from a cancelled task reached the server")
        try await assertHelloWorks()
    }

    func testATaskThatIsNotCancelledCompletes() async throws {
        // The negative control. Without it, the tests above could be passing because something else
        // ends the request, and nobody would know.
        let response = try await client.execute(facadeRequest(server, "/slow?ms=300"))
        XCTAssertEqual(response.code, 200)
        let text = try await response.body.string()
        XCTAssertEqual(text, "eventually")
    }

    func testCancellationPromptlyReleasesTheCaller() async throws {
        let tag = "facade-prompt"
        let request = try facadeRequest(server, "/endless-body?tag=\(tag)")
        let client = self.client!
        let task = Task { try await client.execute(request) }
        try await server.waitUntil("a chunk") { ($0.endlessChunks[tag] ?? 0) >= 1 }

        let start = Date()
        task.cancel()
        assertCancelled(await task.result)
        // A coarse liveness bound: it catches a teardown that deadlocks or waits on the network.
        XCTAssertLessThan(Date().timeIntervalSince(start), 5)
    }
}

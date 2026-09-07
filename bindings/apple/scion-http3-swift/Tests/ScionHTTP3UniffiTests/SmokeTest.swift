// Copyright 2026 Anapaya Systems
import ScionHTTP3Uniffi
import XCTest

/// The whole path from Swift to Rust: a client, one request over a real PocketSCION
/// topology, and a shutdown.
final class SmokeTest: XCTestCase {
    func testAGetReturnsTheServersResponseAndShutdownCloses() async throws {
        let server = try TestServer.start()
        defer { server.stop() }

        let client = try clientFor(server)
        let response = try await client.execute(request: requestTo(server, "/hello"))
        XCTAssertEqual(response.status, 200)
        XCTAssertEqual(String(decoding: response.body, as: UTF8.self), "world")

        await client.shutdown()
        do {
            _ = try await client.execute(request: requestTo(server, "/hello"))
            XCTFail("a request after shutdown succeeded")
        } catch ScionHttp3Error.Closed {
            // What a closed client reports.
        }
    }
}

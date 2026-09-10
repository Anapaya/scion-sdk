// Copyright 2026 Anapaya Systems
import ScionHTTP3
import XCTest

final class FacadeResetTests: XCTestCase {
    func testAResetFaultsWhatWasInFlightAndTheNextRequestRebuilds() async throws {
        let server = try TestServer.start()
        defer { server.stop() }
        // A request timeout beyond the slow response, so that running out of time cannot be what
        // ends the in-flight request. Whatever ends it can then only be the reset.
        let client = try facadeClientFor(server) { $0.requestTimeout = neverTimeout }
        defer { Task { await client.shutdown() } }

        // Warm the connection up, so what follows is a rebuild rather than a first build.
        _ = try await client.execute(facadeRequest(server, "/hello"))
        let before = try await server.stats()
        let started = before.started["/slow"] ?? 0
        let completed = before.requests["/slow"] ?? 0

        let request = try facadeRequest(server, "/slow?ms=120000")
        let slow = Task { try await client.execute(request) }
        try await server.waitUntil("the slow request to reach the server") {
            ($0.started["/slow"] ?? 0) > started
        }

        client.reset()

        let response = try await client.execute(facadeRequest(server, "/hello"))
        XCTAssertEqual(response.code, 200)

        let error = await thrown { try await slow.value }
        XCTAssertNotNil(error as? ScionHttp3Error, "\(String(describing: error))")
        let after = try await server.stats()
        XCTAssertEqual(
            after.requests["/slow"] ?? 0, completed,
            "the server completed the request the reset was supposed to cut off")
    }
}

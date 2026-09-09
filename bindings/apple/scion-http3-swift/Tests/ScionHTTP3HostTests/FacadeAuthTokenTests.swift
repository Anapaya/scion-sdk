// Copyright 2026 Anapaya Systems
import ScionHTTP3
import XCTest

/// The token the stack authenticates with and its renewal.
final class FacadeAuthTokenTests: XCTestCase {
    func testTheConfiguredTokenAuthenticatesARequest() async throws {
        let server = try TestServer.start()
        defer { server.stop() }
        let client = try facadeClientFor(server)
        defer { Task { await client.shutdown() } }

        let response = try await client.execute(facadeRequest(server, "/hello"))
        XCTAssertEqual(response.code, 200)
    }

    func testATokenReplacedAfterConnectivityExistsSurvivesARebuild() async throws {
        let server = try TestServer.start()
        defer { server.stop() }
        let client = try facadeClientFor(server)
        defer { Task { await client.shutdown() } }
        _ = try await client.execute(facadeRequest(server, "/hello"))

        try client.setAuthToken(server.endpoints.authToken + "-renewed")
        client.reset()

        let response = try await client.execute(facadeRequest(server, "/hello"))
        XCTAssertEqual(response.code, 200)
    }

    func testATokenRenewedBeforeTheFirstRequestIsUsedToBuildConnectivity() async throws {
        let server = try TestServer.start()
        defer { server.stop() }
        let client = try facadeClientFor(server)
        defer { Task { await client.shutdown() } }

        try client.setAuthToken(server.endpoints.authToken + "-early")

        let response = try await client.execute(facadeRequest(server, "/hello"))
        XCTAssertEqual(response.code, 200)
    }

    func testAClientBuiltWithoutATokenRefusesOne() async throws {
        let server = try TestServer.start()
        defer { server.stop() }
        let client = try facadeClientFor(server) { $0.authToken = nil }
        defer { Task { await client.shutdown() } }

        do {
            try client.setAuthToken("late")
            XCTFail("a token was accepted by a client built without one")
        } catch ScionHttp3Error.invalidConfiguration {
            // What the facade reports before it asks the stack.
        }
        // Still usable: the topology needs no token.
        let response = try await client.execute(facadeRequest(server, "/hello"))
        XCTAssertEqual(response.code, 200)
    }
}

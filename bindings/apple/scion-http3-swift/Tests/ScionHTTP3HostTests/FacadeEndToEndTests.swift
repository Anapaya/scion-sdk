// Copyright 2026 Anapaya Systems
import ScionHTTP3
import XCTest

/// The facade over the real library: requests that reach the server and responses that come back.
final class FacadeEndToEndTests: XCTestCase {
    private var server: TestServer!
    private var client: ScionHttp3Client!

    override func setUpWithError() throws {
        server = try TestServer.start()
        client = try facadeClientFor(server)
    }

    override func tearDown() async throws {
        await client.shutdown()
        server.stop()
    }

    func testAGetReturnsTheServersResponse() async throws {
        let response = try await client.execute(facadeRequest(server, "/hello"))
        XCTAssertEqual(response.code, 200)
        XCTAssertTrue(response.isSuccessful)
        let text = try await response.body.string()
        XCTAssertEqual(text, "world")
        XCTAssertNil(response.trailers)
    }

    func testAPostRoundTripsItsBodyByteForByte() async throws {
        let body = Data((0..<70_000).map { UInt8(truncatingIfNeeded: $0) })
        let response = try await client.execute(
            facadeRequest(server, "/echo", method: .post, body: .bytes(body)))
        XCTAssertEqual(response.code, 200)
        let echoed = try await response.body.bytes()
        XCTAssertEqual(echoed, body)
    }

    func testHeadersArriveInOrderAndUnmerged() async throws {
        var request = try facadeRequest(server, "/echo-headers")
        request.headers.add("x-first", "1")
        request.headers.add("x-repeat", "a")
        request.headers.add("x-repeat", "b")
        let response = try await client.execute(request)

        struct Field: Decodable {
            let name: String
            let value: String
        }
        let bytes = try await response.body.bytes()
        let fields = try JSONDecoder().decode([Field].self, from: bytes)
        let repeated = fields.filter { $0.name == "x-repeat" }.map(\.value)
        XCTAssertEqual(repeated, ["a", "b"])
        XCTAssertEqual(fields.first { $0.name == "x-first" }?.value, "1")
    }

    func testTheBodysMediaTypeReachesTheServer() async throws {
        let response = try await client.execute(
            facadeRequest(server, "/echo-headers", method: .post, body: .json("{}")))
        let text = try await response.body.string()
        XCTAssertTrue(text.contains("application/json"), text)
    }

    func testRepeatedResponseHeadersAreKept() async throws {
        let response = try await client.execute(facadeRequest(server, "/repeated-headers"))
        XCTAssertEqual(response.headers.values("set-cookie"), ["a=1", "b=2"])
    }

    func testATrailingHeaderSectionArrivesSeparately() async throws {
        let response = try await client.execute(facadeRequest(server, "/trailers"))
        let text = try await response.body.string()
        XCTAssertEqual(text, "with trailers")
        XCTAssertEqual(response.trailers?["x-checksum"], "42")
    }

    func testANon2xxStatusIsAResponse() async throws {
        let response = try await client.execute(facadeRequest(server, "/status/404"))
        XCTAssertEqual(response.code, 404)
        XCTAssertFalse(response.isSuccessful)
    }

    func testTheMethodIsSentAsWritten() async throws {
        let response = try await client.execute(facadeRequest(server, "/method", method: "PURGE"))
        let text = try await response.body.string()
        XCTAssertEqual(text, "PURGE")
    }

    func testANonTextBodyIsNotDecodedOnTheWay() async throws {
        let response = try await client.execute(facadeRequest(server, "/invalid-utf8"))
        let bytes = try await response.body.bytes()
        XCTAssertEqual(bytes, Data([0xFF, 0xFE]))
        let error = await thrown { try await response.body.string() } as? ScionHttp3Error
        guard case .invalidBody? = error else { return XCTFail("\(String(describing: error))") }
    }

    func testTheShorthandsWork() async throws {
        let impatient = try facadeClientFor(server) { $0.connectTimeout = shortConnectTimeout }
        defer { Task { await impatient.shutdown() } }

        let error = await thrown { try await impatient.get(server.url("/hello")) }
            as? ScionHttp3Error
        assertTheHostCouldNotBeReached(error)
    }

    func testWarmUpEstablishesConnectivityAheadOfTheFirstRequest() async throws {
        let impatient = try facadeClientFor(server) { $0.connectTimeout = shortConnectTimeout }
        defer { Task { await impatient.shutdown() } }

        let error = await thrown { try await impatient.warmUp(server.url("/")) } as? ScionHttp3Error
        assertTheHostCouldNotBeReached(error)
        // Connectivity was built for the attempt, and the client is still usable.
        let response = try await impatient.execute(facadeRequest(server, "/hello"))
        XCTAssertEqual(response.code, 200)
    }

    func testASecondRequestReusesTheConnection() async throws {
        let before = try await server.stats().requests["/hello"] ?? 0
        _ = try await client.execute(facadeRequest(server, "/hello"))
        _ = try await client.execute(facadeRequest(server, "/hello"))
        let after = try await server.stats().requests["/hello"] ?? 0
        XCTAssertEqual(after, before + 2)
    }

    func testARequestAfterAServerRestartReachesTheServerAgain() async throws {
        _ = try await client.execute(facadeRequest(server, "/hello"))
        try await server.restartServer()

        // The server keeps its socket and replaces only the endpoint reading it, so nothing tells
        // the client that its connection is gone:.
        var request = try facadeRequest(server, "/hello")
        request.requestTimeout = 2
        let error = await thrown { try await client.execute(request) } as? ScionHttp3Error
        XCTAssertTrue(error?.isRetryable ?? false, "\(String(describing: error))")

        // Left alone the client sits out the QUIC idle timeout before it gives up on that
        // connection, because a peer that answers nothing is what a lost network also looks like.
        client.reset()
        let response = try await client.execute(facadeRequest(server, "/hello"))
        XCTAssertEqual(response.code, 200)
    }
}

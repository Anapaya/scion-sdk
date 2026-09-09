// Copyright 2026 Anapaya Systems
import ScionHTTP3
import XCTest

/// Each failure the stack reports, provoked for real and read back as the facade's case.
final class FacadeErrorBridgingTests: XCTestCase {
    func testAMalformedTargetIsRefusedBeforeAnythingIsSent() async throws {
        let server = try TestServer.start()
        defer { server.stop() }
        let client = try facadeClientFor(server)
        defer { Task { await client.shutdown() } }

        var request = ScionHttp3Request(url: server.url("/hello"))
        request.targets = [try ScionAddress("1-ff00:0:110,nonsense")]
        let error = await thrown { try await client.execute(request) } as? ScionHttp3Error
        guard case .invalidRequest? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertFalse(error?.isRetryable ?? true)
    }

    func testARequestAfterShutdownIsClosed() async throws {
        let server = try TestServer.start()
        defer { server.stop() }
        let client = try facadeClientFor(server)
        _ = try await client.execute(facadeRequest(server, "/hello"))

        await client.shutdown()
        let error = await thrown { try await client.execute(facadeRequest(server, "/hello")) }
        XCTAssertEqual(error as? ScionHttp3Error, .closed)
    }

    func testARequestPastItsDeadlineTimesOutInTheRequestPhase() async throws {
        let server = try TestServer.start()
        defer { server.stop() }
        let client = try facadeClientFor(server)
        defer { Task { await client.shutdown() } }

        var request = try facadeRequest(server, "/slow?ms=600000")
        request.requestTimeout = 0.5
        let error = await thrown { try await client.execute(request) } as? ScionHttp3Error
        guard case .timeout(let phase, let after, _, let retryable)? = error else {
            return XCTFail("\(String(describing: error))")
        }
        XCTAssertEqual(phase, .request)
        XCTAssertEqual(after, 0.5)
        XCTAssertTrue(retryable)
    }

    func testAResponseOverTheLimitReportsTheLimit() async throws {
        let server = try TestServer.start()
        defer { server.stop() }
        let client = try facadeClientFor(server)
        defer { Task { await client.shutdown() } }

        var request = try facadeRequest(server, "/big?bytes=4096")
        request.maxResponseBodyBytes = 1024
        let error = await thrown { try await client.execute(request) } as? ScionHttp3Error
        guard case .bodyTooLarge(let limit, _, let retryable)? = error else {
            return XCTFail("\(String(describing: error))")
        }
        XCTAssertEqual(limit, 1024)
        XCTAssertFalse(retryable)
    }

    func testAServerAllowingNoRequestStreamsReportsTheConnectionLimit() async throws {
        let server = try TestServer.start(arguments: ["--max-streams", "0"])
        defer { server.stop() }
        let client = try facadeClientFor(server)
        defer { Task { await client.shutdown() } }

        let error = await thrown { try await client.execute(facadeRequest(server, "/hello")) }
            as? ScionHttp3Error
        guard case .connectionLimit? = error else { return XCTFail("\(String(describing: error))") }
    }

    func testAServerThatWillNotSpeakHttp3ReportsConnect() async throws {
        let server = try TestServer.start(arguments: ["--alpn", "http/1.1"])
        defer { server.stop() }
        let client = try facadeClientFor(server) { $0.connectTimeout = 5 }
        defer { Task { await client.shutdown() } }

        let error = await thrown { try await client.execute(facadeRequest(server, "/hello")) }
            as? ScionHttp3Error
        guard case .connect? = error else { return XCTFail("\(String(describing: error))") }
    }

    func testAnotherAuthoritysCertificateIsRejectedWithPinnedAnchors() async throws {
        let server = try TestServer.start()
        defer { server.stop() }
        let client = try facadeClientFor(server) {
            $0.trust = try .pinned(Data(server.endpoints.wrongCaPem.utf8))
            $0.connectTimeout = 5
        }
        defer { Task { await client.shutdown() } }

        let error = await thrown { try await client.execute(facadeRequest(server, "/hello")) }
            as? ScionHttp3Error
        guard case .connect? = error else { return XCTFail("\(String(describing: error))") }
    }

    func testTheSystemTrustRejectsTheTestServersOwnAuthority() async throws {
        let server = try TestServer.start()
        defer { server.stop() }
        let client = try facadeClientFor(server) {
            $0.trust = .systemDefault
            $0.connectTimeout = 5
        }
        defer { Task { await client.shutdown() } }

        let error = await thrown { try await client.execute(facadeRequest(server, "/hello")) }
            as? ScionHttp3Error
        guard case .tls(let host, _, let retryable)? = error else {
            return XCTFail("\(String(describing: error))")
        }
        XCTAssertEqual(host, "localhost")
        XCTAssertFalse(retryable)
    }

    func testAnEndhostApiThatIsNotThereReportsConnectivity() async throws {
        var configuration = ScionHttp3Client.Configuration(endhostApi: "http://127.0.0.1:9")
        configuration.connectTimeout = 5
        let client = try ScionHttp3Client(configuration: configuration)
        defer { Task { await client.shutdown() } }

        let error = await thrown {
            try await client.execute(ScionHttp3Request(url: "https://localhost:1/hello"))
        } as? ScionHttp3Error
        guard case .connectivity? = error else { return XCTFail("\(String(describing: error))") }
    }

    func testDisabledVerificationAcceptsTheServer() async throws {
        let server = try TestServer.start()
        defer { server.stop() }
        let client = try facadeClientFor(server) { $0.trust = .insecureNoVerify }
        defer { Task { await client.shutdown() } }

        let response = try await client.execute(facadeRequest(server, "/hello"))
        XCTAssertEqual(response.code, 200)
    }
}

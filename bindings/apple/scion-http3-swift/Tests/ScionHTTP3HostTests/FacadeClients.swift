// Copyright 2026 Anapaya Systems
import Foundation
import ScionHTTP3
import XCTest

// The facade over the real library against the test server.

/// A never-expiring request timeout so that no deadline can be mistaken for a cancellation.
let neverTimeout: TimeInterval = 600

/// The connect timeout for a call that is going to fail on the host so it fails promptly.
let shortConnectTimeout: TimeInterval = 3

/// A facade client that trusts the server's own authority.
func facadeClientFor(
    _ server: TestServer,
    configure: (inout ScionHttp3Client.Configuration) throws -> Void = { _ in }
) throws -> ScionHttp3Client {
    var configuration = ScionHttp3Client.Configuration(
        endhostApi: server.endpoints.endhostApiUrl, authToken: server.endpoints.authToken)
    configuration.trust = try .pinned(Data(server.endpoints.caPem.utf8))
    // Shortened from the defaults so that a test which is going to fail does so while someone is
    // still watching.
    configuration.connectTimeout = 15
    configuration.requestTimeout = 30
    try configure(&configuration)
    return try ScionHttp3Client(configuration: configuration)
}

/// A request to `path` on the server, addressed directly.
func facadeRequest(
    _ server: TestServer, _ path: String, method: ScionHttp3Request.Method = .get,
    body: ScionHttp3RequestBody? = nil
) throws -> ScionHttp3Request {
    var request = ScionHttp3Request(url: server.url(path), method: method, body: body)
    request.target = try ScionAddress(server.endpoints.target)
    return request
}

/// Asserts that a call which was given a URL and no target failed on the URL's host.
func assertTheHostCouldNotBeReached(
    _ error: ScionHttp3Error?, file: StaticString = #filePath, line: UInt = #line
) {
    switch error {
    case .resolution, .timeout(.connect, _, _, _):
        break
    default:
        XCTFail(
            "expected the host to be unreachable, got \(String(describing: error))", file: file,
            line: line)
    }
}

/// Runs `body` and returns what it threw, or fails the test if it threw nothing.
func thrown<T>(
    _ body: () async throws -> T, file: StaticString = #filePath, line: UInt = #line
) async -> (any Error)? {
    do {
        _ = try await body()
        XCTFail("expected an error, got a result", file: file, line: line)
        return nil
    } catch {
        return error
    }
}

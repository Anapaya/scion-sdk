// Copyright 2026 Anapaya Systems

// ANCHOR: full-sample
import Foundation
import ScionHTTP3

/// One HTTP/3 request over SCION.
final class HelloScion: Sendable {
    struct Reply {
        let code: Int
        let body: String
    }

    private let network: LocalNetwork
    private let client: ScionHttp3Client

    // ANCHOR: build-client
    init(network: LocalNetwork) throws {
        self.network = network
        var configuration = ScionHttp3Client.Configuration(
            // Where the client discovers its SCION connectivity.
            endhostApi: network.endhostApiUrl,
            authToken: network.authToken)
        configuration.trust = try .pinned(Data(network.caPem.utf8))
        configuration.connectTimeout = 30
        configuration.requestTimeout = 60
        client = try ScionHttp3Client(configuration: configuration)
    }
    // ANCHOR_END: build-client

    // ANCHOR: request
    /// `GET /hello`, which the test server answers with `world`.
    func hello() async throws -> Reply {
        var request = ScionHttp3Request(url: network.baseUrl + "/hello")
        // The test network publishes no records for its server, so address it directly.
        request.target = try ScionAddress(network.target)

        let response = try await client.execute(request)
        return Reply(code: response.code, body: try await response.body.string())
    }
    // ANCHOR_END: request

    // ANCHOR: lifetime
    /// Releases the client's connections.
    ///
    /// Waits until each connection has told its peer it is going away. A client that is dropped
    /// without this still closes its connections in the background and whenever ARC gets to it.
    func shutdown() async {
        await client.shutdown()
    }
    // ANCHOR_END: lifetime
}
// ANCHOR_END: full-sample

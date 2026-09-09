// Copyright 2026 Anapaya Systems
import Foundation
import ScionHTTP3Uniffi

/// A client that trusts the server's own authority.
func clientFor(
    _ server: TestServer, configure: (inout ClientConfig) -> Void = { _ in }
) throws -> ScionHttp3Client {
    var config = defaultClientConfig(endhostApiUrl: server.endpoints.endhostApiUrl)
    config.authToken = server.endpoints.authToken
    config.trust = .pem(pem: Data(server.endpoints.caPem.utf8))
    config.connectTimeoutMs = 15_000
    config.requestTimeoutMs = 30_000
    configure(&config)
    return try ScionHttp3Client(config: config)
}

/// A request to `path` on the server, addressed directly.
func requestTo(_ server: TestServer, _ path: String) -> HttpRequest {
    HttpRequest(url: server.url(path), targets: [server.endpoints.target])
}

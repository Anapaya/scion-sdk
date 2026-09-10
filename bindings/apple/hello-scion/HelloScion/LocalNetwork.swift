// Copyright 2026 Anapaya Systems

import Foundation

/// Where the local test network is.
///
/// A real app knows all of this before it is built. `scion-h3-test-server` decides all four when it
/// starts, because it takes ephemeral ports, mints an auth token per run and generates a throwaway
/// certificate authority.
struct LocalNetwork: Decodable, Sendable {
    let endhostApiUrl: String
    let authToken: String
    let baseUrl: String
    let target: String
    let caPem: String

    enum CodingKeys: String, CodingKey {
        case endhostApiUrl = "endhost_api_url"
        case authToken = "auth_token"
        case baseUrl = "base_url"
        case target
        case caPem = "ca_pem"
    }

    /// The control API of a test server started with `--control-port 7443`. The simulator shares
    /// the Mac's network, so the loopback address the server binds is the simulator's too.
    private static let controlUrl = "http://127.0.0.1:7443/info"

    /// Reads the description the test server serves. Throws if it is not running.
    static func discover() async throws -> LocalNetwork {
        let (data, _) = try await URLSession.shared.data(from: URL(string: controlUrl)!)
        return try JSONDecoder().decode(LocalNetwork.self, from: data)
    }
}

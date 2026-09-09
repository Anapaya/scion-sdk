// Copyright 2026 Anapaya Systems
import Foundation

/// Which transport to prefer for carrying traffic.
public enum PreferredUnderlay: Sendable, Equatable {
    case snap
    case udp
}

/// Settings for the SNAP transport.
public struct SnapConfig: Sendable, Equatable {
    /// Selects one of several data planes the endhost API offers. Cannot be negative.
    public var dataPlaneIndex: Int?

    /// A fixed 32-byte X25519 private key identifying this endpoint to the SNAP server.
    ///
    /// Without one, a fresh key is generated every time connectivity is established. Since
    /// connectivity is re-established on every network change, a mobile client changes identity
    /// often, which matters wherever the server keeps per-endpoint state.
    public var staticIdentity: Data?

    public init(dataPlaneIndex: Int? = nil, staticIdentity: Data? = nil) {
        self.dataPlaneIndex = dataPlaneIndex
        self.staticIdentity = staticIdentity
    }
}

/// Settings for the UDP transport.
public struct UdpConfig: Sendable, Equatable {
    /// Sends from these local addresses instead of letting the platform choose.
    public var outboundIps: [String]

    /// How often to refresh the next-hop information the UDP transport routes by, in seconds.
    public var nextHopResolverFetchInterval: TimeInterval?

    public init(outboundIps: [String] = [], nextHopResolverFetchInterval: TimeInterval? = nil) {
        self.outboundIps = outboundIps
        self.nextHopResolverFetchInterval = nextHopResolverFetchInterval
    }
}

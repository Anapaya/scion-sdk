// Copyright 2026 Anapaya Systems

/// What makes one network path different from another, for the purpose of deciding that
/// connectivity has to be rebuilt.
struct NetworkIdentity: Sendable, Equatable {
    /// The name of the interface the path prefers or nil when the path has none.
    let interfaceName: String?

    /// The kind of that interface: `wifi`, `cellular`, `wiredEthernet`, `loopback`, or `other`.
    let interfaceType: String?

    /// The path's gateways in the order the platform lists them.
    let gateways: [String]

    /// Whether the platform says the path can carry traffic.
    let satisfied: Bool

    /// Whether this observation says anything about a usable path.
    var isUsable: Bool { satisfied && interfaceName != nil }

    /// Whether this is the same path as `other`.
    func isSameNetwork(as other: NetworkIdentity) -> Bool {
        interfaceName == other.interfaceName && interfaceType == other.interfaceType
            && gateways == other.gateways
    }
}

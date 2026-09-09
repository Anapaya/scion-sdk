// Copyright 2026 Anapaya Systems
import Foundation

/// Everything a client was configured with.
///
/// Every setting except the endhost API and the trust anchors is optional and nil means "whatever
/// the SCION stack does".
struct ClientSettings: Sendable, Equatable {
    let endhostApiUrl: String
    let authToken: String?
    let preferredUnderlay: PreferredUnderlay?
    let snap: SnapConfig
    let udp: UdpConfig
    let trust: TrustAnchors
    let connectTimeout: TimeInterval?
    let requestTimeout: TimeInterval?
    let idleConnectionTimeout: TimeInterval?
    let connectionAttemptDelay: TimeInterval?
    let maxOrigins: Int?
    let maxResponseBodyBytes: Int?

    /// Throws `ScionHttp3Error.invalidConfiguration` for the first setting that cannot be right.
    init(_ configuration: ScionHttp3Client.Configuration) throws {
        try Self.validateEndhostApiUrl(configuration.endhostApi)
        if let token = configuration.authToken, token.isEmpty {
            throw ScionHttp3Error.invalidConfiguration(detail: "an auth token cannot be empty")
        }
        try Self.requirePositive("connectTimeout", configuration.connectTimeout)
        try Self.requirePositive("requestTimeout", configuration.requestTimeout)
        try Self.requirePositive("idleConnectionTimeout", configuration.idleConnectionTimeout)
        try Self.requirePositive("connectionAttemptDelay", configuration.connectionAttemptDelay)
        if let maxOrigins = configuration.maxOrigins, maxOrigins < 1 {
            throw ScionHttp3Error.invalidConfiguration(
                detail: "maxOrigins has to be at least 1, got \(maxOrigins)")
        }
        if let bytes = configuration.maxResponseBodyBytes, bytes <= 0 {
            throw ScionHttp3Error.invalidConfiguration(
                detail: "maxResponseBodyBytes has to be positive, got \(bytes) bytes")
        }
        if let index = configuration.snap.dataPlaneIndex, index < 0 {
            throw ScionHttp3Error.invalidConfiguration(
                detail: "a data plane index cannot be negative, got \(index)")
        }
        if let key = configuration.snap.staticIdentity, key.count != 32 {
            throw ScionHttp3Error.invalidConfiguration(
                detail: "a SNAP static identity is a 32-byte X25519 private key, "
                    + "got \(key.count) bytes")
        }
        if configuration.udp.outboundIps.contains(where: {
            $0.trimmingCharacters(in: .whitespaces).isEmpty
        }) {
            throw ScionHttp3Error.invalidConfiguration(detail: "an outbound IP cannot be blank")
        }
        try Self.requirePositive(
            "nextHopResolverFetchInterval", configuration.udp.nextHopResolverFetchInterval)

        endhostApiUrl = configuration.endhostApi
        authToken = configuration.authToken
        preferredUnderlay = configuration.preferredUnderlay
        snap = configuration.snap
        udp = configuration.udp
        trust = configuration.trust
        connectTimeout = configuration.connectTimeout
        requestTimeout = configuration.requestTimeout
        idleConnectionTimeout = configuration.idleConnectionTimeout
        connectionAttemptDelay = configuration.connectionAttemptDelay
        maxOrigins = configuration.maxOrigins
        maxResponseBodyBytes = configuration.maxResponseBodyBytes
    }

    /// How long a client may go unused before a request re-checks the network itself.
    var idleThreshold: TimeInterval {
        idleConnectionTimeout.map(StalenessTracker.idleThreshold(forIdleConnectionTimeout:))
            ?? Self.defaultIdleThreshold
    }

    static let defaultIdleThreshold: TimeInterval = 50

    private static func requirePositive(_ name: String, _ value: TimeInterval?) throws {
        if let value, !(value > 0) || !value.isFinite {
            throw ScionHttp3Error.invalidConfiguration(
                detail: "\(name) has to be positive and finite, got \(value) s")
        }
    }

    private static func validateEndhostApiUrl(_ url: String) throws {
        if url.isEmpty {
            throw ScionHttp3Error.invalidConfiguration(
                detail: "endhostApi is required: it is the address the client discovers SCION "
                    + "connectivity through. A local PocketSCION topology is reached at the "
                    + "endhost API URL it prints, for example http://127.0.0.1:8041.")
        }
        guard let components = URLComponents(string: url) else {
            throw ScionHttp3Error.invalidConfiguration(
                detail: "endhostApi \"\(url)\" is not a valid URL")
        }
        guard let scheme = components.scheme, let host = components.host, !host.isEmpty else {
            throw ScionHttp3Error.invalidConfiguration(
                detail: "endhostApi \"\(url)\" needs a scheme and a host, for example "
                    + "https://endhost-api.example.org")
        }
        let lowered = scheme.lowercased()
        if lowered != "http" && lowered != "https" {
            throw ScionHttp3Error.invalidConfiguration(
                detail: "endhostApi \"\(url)\" has to be http or https, not \(scheme)")
        }
    }
}

func warnIfVerificationDisabled(_ trust: TrustAnchors, log: any LibraryLog) {
    guard trust.kind == .insecureNoVerify else { return }
    log.error(
        "TLS certificate verification is DISABLED for this ScionHttp3Client. Every response could "
            + "come from anyone on the path. This is for local testing only. "
            + "TrustAnchors.insecureNoVerify should not ship. Use TrustAnchors.pinned(_:) with the "
            + "deployment's own certificate authority instead.")
}

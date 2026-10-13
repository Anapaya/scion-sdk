// Copyright 2026 Anapaya Systems
import Foundation

/// The source that the client takes its tokens from, for
/// `ScionHttp3Client.Configuration.authTokenSource`.
public struct AuthTokenSource: Sendable, Equatable {
    enum Kind: Sendable, Equatable {
        case anapayaAa(apiKey: String, aaUrl: String)
    }

    let kind: Kind

    /// Exchanges an Anapaya AA API key for tokens, and renews the token. `aaUrl` has to be
    /// `https`, or `http` to a loopback host.
    ///
    /// A failed exchange fails the request with `ScionHttp3Error.connectivity`. `isRetryable` is
    /// false when the AA refused the key.
    public static func anapayaAa(apiKey: String, aaUrl: String) -> AuthTokenSource {
        AuthTokenSource(kind: .anapayaAa(apiKey: apiKey, aaUrl: aaUrl))
    }
}

extension AuthTokenSource: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String {
        switch kind {
        case let .anapayaAa(_, aaUrl):
            return "AuthTokenSource.anapayaAa(apiKey: <redacted>, aaUrl: \(aaUrl))"
        }
    }

    public var debugDescription: String { description }
}

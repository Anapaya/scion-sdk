// Copyright 2026 Anapaya Systems
import Foundation

/// Everything a request can fail with.
///
/// Each case is something a caller can act on differently. A cancelled request does not throw one
/// of these: it throws Swift's `CancellationError`, as every other cancelled task does.
///
/// `isRetryable` says whether the same request may succeed if it is issued again.
///
/// `detail` is the underlying failure and its causes, for logs and bug reports. It is
/// human-readable and not a stable format.
public enum ScionHttp3Error: Error, Sendable, Equatable {
    /// Which part of a request ran out of time.
    public enum TimeoutPhase: Sendable, Equatable {
        /// Establishing connectivity to the origin.
        case connect
        /// Waiting for the response head.
        case request
        /// Collecting the response body.
        case body
        /// A phase this version of the library does not distinguish.
        case other
    }

    /// The client could not establish the connectivity a request needs, before it sent anything.
    case connectivity(detail: String, retryable: Bool)

    /// The request's host has no usable SCION address records.
    ///
    /// Either the name does not resolve, or it resolves to nothing this client can reach. Set
    /// `ScionHttp3Request.target` to address a host that has no records at all.
    case resolution(host: String, detail: String, retryable: Bool)

    /// Reaching the origin failed: the socket, the QUIC handshake, or the peer refusing.
    case connect(host: String, port: Int, detail: String, retryable: Bool)

    /// The origin's certificate was rejected, or the origin does not speak HTTP/3.
    ///
    /// A private deployment whose certificate is signed by an internal authority needs
    /// `TrustAnchors.pinned(_:)`; the platform anchors do not accept it.
    case tls(host: String, detail: String, retryable: Bool)

    /// The origin reset the request's stream.
    ///
    /// `code` is the HTTP/3 application error code.
    case streamReset(code: UInt64, detail: String, retryable: Bool)

    /// The origin broke HTTP/3 itself: a malformed frame or a header section this client rejects.
    case protocolViolation(detail: String, retryable: Bool)

    /// The origin allows no further concurrent requests on the connection.
    case connectionLimit(detail: String, retryable: Bool)

    /// The response body exceeded `limit` bytes and was not collected.
    ///
    /// Raise the limit for one request with `ScionHttp3Request.maxResponseBodyBytes` or for every
    /// request with `ScionHttp3Client.Configuration.maxResponseBodyBytes`.
    case bodyTooLarge(limit: Int, detail: String, retryable: Bool)

    /// A deadline of `after` seconds expired in `phase`.
    case timeout(phase: TimeoutPhase, after: TimeInterval, detail: String, retryable: Bool)

    /// A body could not be decoded as requested.
    ///
    /// `ScionHttp3ResponseBody.string(maxSize:)` throws this when the bytes are not valid UTF-8.
    case invalidBody(detail: String, retryable: Bool)

    /// The request was rejected before anything was sent.
    case invalidRequest(detail: String)

    /// A configuration value cannot be right.
    case invalidConfiguration(detail: String)

    /// The client is shut down.
    case closed

    /// A failure this version of the library does not describe more precisely.
    case internalError(detail: String)

    /// Whether the same request may succeed if it is issued again.
    public var isRetryable: Bool {
        switch self {
        case .connectivity(_, let retryable),
            .resolution(_, _, let retryable),
            .connect(_, _, _, let retryable),
            .tls(_, _, let retryable),
            .streamReset(_, _, let retryable),
            .protocolViolation(_, let retryable),
            .connectionLimit(_, let retryable),
            .bodyTooLarge(_, _, let retryable),
            .timeout(_, _, _, let retryable),
            .invalidBody(_, let retryable):
            return retryable
        case .invalidRequest, .invalidConfiguration, .closed, .internalError:
            return false
        }
    }

    /// The underlying failure and its causes.
    public var detail: String {
        switch self {
        case .connectivity(let detail, _),
            .resolution(_, let detail, _),
            .connect(_, _, let detail, _),
            .tls(_, let detail, _),
            .streamReset(_, let detail, _),
            .protocolViolation(let detail, _),
            .connectionLimit(let detail, _),
            .bodyTooLarge(_, let detail, _),
            .timeout(_, _, let detail, _),
            .invalidBody(let detail, _),
            .invalidRequest(let detail),
            .invalidConfiguration(let detail),
            .internalError(let detail):
            return detail
        case .closed:
            return Self.closedDetail
        }
    }

    static let closedDetail =
        "this ScionHttp3Client is shut down. Build another one to make requests again."
}

extension ScionHttp3Error: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .resolution(let host, let detail, _), .tls(let host, let detail, _):
            return "\(host): \(detail)"
        case .connect(let host, let port, let detail, _):
            return "\(host):\(port): \(detail)"
        case .streamReset(let code, let detail, _):
            return "stream reset, code \(code): \(detail)"
        case .bodyTooLarge(let limit, _, _):
            return "response body exceeds \(limit) bytes"
        case .timeout(let phase, let after, let detail, _):
            return "timed out after \(after)s in \(phase): \(detail)"
        case .connectivity, .protocolViolation, .connectionLimit, .invalidBody, .invalidRequest,
            .invalidConfiguration, .closed, .internalError:
            return detail
        }
    }
}

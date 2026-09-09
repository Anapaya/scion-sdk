// Copyright 2026 Anapaya Systems
import Foundation
internal import ScionHTTP3Uniffi

typealias FfiClient = ScionHTTP3Uniffi.ScionHttp3Client
typealias FfiError = ScionHTTP3Uniffi.ScionHttp3Error
typealias FfiTrustAnchors = ScionHTTP3Uniffi.TrustAnchors
typealias FfiSnapConfig = ScionHTTP3Uniffi.SnapConfig
typealias FfiUdpConfig = ScionHTTP3Uniffi.UdpConfig
typealias FfiTimeoutPhase = ScionHTTP3Uniffi.TimeoutPhase

/// The request as the stack receives it.
///
/// Throws `ScionHttp3Error.invalidRequest` for what the request itself gets wrong, before anything
/// is sent.
func ffiRequest(from request: ScionHttp3Request) throws -> HttpRequest {
    try request.validate()
    var headers = request.headers
    if let contentType = request.body?.contentType {
        headers.addIfAbsent("content-type", contentType)
    }
    return HttpRequest(
        url: request.url,
        method: request.method.rawValue,
        headers: headers.map { Header(name: $0.name, value: $0.value) },
        // Absent and empty are different below: absent sends no body at all, where an empty one
        // sends a body of zero bytes. Preserve which the caller chose.
        body: request.body?.data,
        targets: request.targets.map(\.description),
        requestTimeoutMs: request.requestTimeout.map(milliseconds),
        maxResponseBodyBytes: request.maxResponseBodyBytes.map { UInt64(clamping: $0) })
}

/// The response as the application sees it.
func publicResponse(
    from response: HttpResponse, to request: ScionHttp3Request, keepAlive: any Sendable
) -> ScionHttp3Response {
    ScionHttp3Response(
        code: Int(response.status),
        headers: publicHeaders(response.headers),
        body: ScionHttp3ResponseBody(response.body, keepAlive: keepAlive),
        trailers: response.trailers.isEmpty ? nil : publicHeaders(response.trailers),
        request: request)
}

private func publicHeaders(_ headers: [Header]) -> ScionHttp3Headers {
    ScionHttp3Headers(
        entries: headers.map { ScionHttp3Headers.Entry(name: $0.name, value: $0.value) })
}

/// The public error for a failure from the stack; any other error passes through unchanged.
func publicError(_ error: any Error) -> any Error {
    guard let ffi = error as? FfiError else { return error }
    switch ffi {
    case .StackBuild(let retryable, let detail):
        return ScionHttp3Error.connectivity(detail: detail, retryable: retryable)
    case .Resolution(let host, let retryable, let detail):
        return ScionHttp3Error.resolution(host: host, detail: detail, retryable: retryable)
    case .Connect(let host, let port, let retryable, let detail):
        return ScionHttp3Error.connect(
            host: host, port: Int(port), detail: detail, retryable: retryable)
    case .Tls(let host, let retryable, let detail):
        return ScionHttp3Error.tls(host: host, detail: detail, retryable: retryable)
    case .StreamReset(let code, let retryable, let detail):
        return ScionHttp3Error.streamReset(code: code, detail: detail, retryable: retryable)
    case .Protocol(let retryable, let detail):
        return ScionHttp3Error.protocolViolation(detail: detail, retryable: retryable)
    case .ConnectionLimit(let retryable, let detail):
        return ScionHttp3Error.connectionLimit(detail: detail, retryable: retryable)
    case .BodyTooLarge(let limit, let retryable, let detail):
        return ScionHttp3Error.bodyTooLarge(
            limit: Int(clamping: limit), detail: detail, retryable: retryable)
    case .Timeout(let phase, let timeoutMs, let retryable, let detail):
        return ScionHttp3Error.timeout(
            phase: publicPhase(phase), after: TimeInterval(timeoutMs) / 1000, detail: detail,
            retryable: retryable)
    case .InvalidRequest(_, let detail):
        return ScionHttp3Error.invalidRequest(detail: detail)
    case .Closed:
        return ScionHttp3Error.closed
    case .Cancelled:
        return CancellationError()
    case .Internal(_, let detail):
        return ScionHttp3Error.internalError(detail: detail)
    }
}

private func publicPhase(_ phase: FfiTimeoutPhase) -> ScionHttp3Error.TimeoutPhase {
    switch phase {
    case .connect: return .connect
    case .request: return .request
    case .body: return .body
    case .other: return .other
    }
}

/// Whole milliseconds, as the FFI carries every duration.
func milliseconds(_ seconds: TimeInterval) -> UInt64 {
    UInt64(clamping: Int64((seconds * 1000).rounded()))
}

extension ClientSettings {
    /// Applies the configured settings on top of the stack's own defaults.
    func applyTo(_ base: ClientConfig) -> ClientConfig {
        var config = base
        config.endhostApiUrl = endhostApiUrl
        config.authToken = authToken ?? base.authToken
        config.preferredUnderlay = preferredUnderlay.map(ffiUnderlay) ?? base.preferredUnderlay
        config.snap = FfiSnapConfig(
            dpIndex: snap.dataPlaneIndex.map { UInt32(clamping: $0) } ?? base.snap.dpIndex,
            staticIdentity: snap.staticIdentity ?? base.snap.staticIdentity)
        config.udp = FfiUdpConfig(
            outboundIps: udp.outboundIps.isEmpty ? base.udp.outboundIps : udp.outboundIps,
            nextHopResolverFetchIntervalMs: udp.nextHopResolverFetchInterval.map(milliseconds)
                ?? base.udp.nextHopResolverFetchIntervalMs)
        config.trust = ffiTrustAnchors(trust)
        config.connectTimeoutMs = connectTimeout.map(milliseconds) ?? base.connectTimeoutMs
        config.requestTimeoutMs = requestTimeout.map(milliseconds) ?? base.requestTimeoutMs
        config.idleConnectionTimeoutMs =
            idleConnectionTimeout.map(milliseconds) ?? base.idleConnectionTimeoutMs
        config.maxOrigins = maxOrigins.map { UInt32(clamping: $0) } ?? base.maxOrigins
        config.connectionAttemptDelayMs =
            connectionAttemptDelay.map(milliseconds) ?? base.connectionAttemptDelayMs
        config.maxResponseBodyBytes =
            maxResponseBodyBytes.map { UInt64(clamping: $0) } ?? base.maxResponseBodyBytes
        return config
    }
}

private func ffiUnderlay(_ underlay: PreferredUnderlay) -> Underlay {
    switch underlay {
    case .snap: return .snap
    case .udp: return .udp
    }
}

/// The trust anchors the stack should use.
func ffiTrustAnchors(_ trust: TrustAnchors) -> FfiTrustAnchors {
    switch trust.kind {
    case .systemDefault: return .systemDefault
    case .pinned(let pem): return .pem(pem: pem)
    case .insecureNoVerify: return .insecureNoVerify
    }
}

// Copyright 2026 Anapaya Systems

/// A response with its body already received.
///
/// A non-2xx status is a response. Errors are for requests that did not produce a response at all.
public struct ScionHttp3Response: Sendable {
    /// The status code.
    public let code: Int

    /// The response's header section.
    public let headers: ScionHttp3Headers

    /// The body. Always present and empty when the response carried none.
    public let body: ScionHttp3ResponseBody

    /// The trailing header section or nil when the response had none.
    ///
    /// Nil and empty are different: nil means no trailer section was sent. An empty section means
    /// one was sent and carried nothing.
    public let trailers: ScionHttp3Headers?

    /// The request this answers.
    public let request: ScionHttp3Request

    /// Whether `code` is in 200...299.
    public var isSuccessful: Bool { (200...299).contains(code) }

    init(
        code: Int, headers: ScionHttp3Headers, body: ScionHttp3ResponseBody,
        trailers: ScionHttp3Headers?, request: ScionHttp3Request
    ) {
        self.code = code
        self.headers = headers
        self.body = body
        self.trailers = trailers
        self.request = request
    }
}

extension ScionHttp3Response: CustomStringConvertible {
    public var description: String { "\(code) \(request.method) \(request.url)" }
}

// Copyright 2026 Anapaya Systems
import Foundation

/// One request: where to send it, what to send, and the per-request limits that apply to it.
///
/// It is safe to issue more than once and to change after a copy was sent. Everything a request can
/// get wrong is reported when it is sent as `ScionHttp3Error.invalidRequest`.
public struct ScionHttp3Request: Sendable, Equatable {
    /// An HTTP method: an RFC 9110 token, sent exactly as written.
    public struct Method: Sendable, Hashable, RawRepresentable, ExpressibleByStringLiteral,
        CustomStringConvertible
    {
        public let rawValue: String

        public init(rawValue: String) {
            self.rawValue = rawValue
        }

        public init(_ rawValue: String) {
            self.rawValue = rawValue
        }

        public init(stringLiteral value: String) {
            self.rawValue = value
        }

        public var description: String { rawValue }

        public static let get = Method("GET")
        public static let post = Method("POST")
        public static let put = Method("PUT")
        public static let patch = Method("PATCH")
        public static let delete = Method("DELETE")
        public static let head = Method("HEAD")

        func validate() throws {
            if rawValue.isEmpty {
                throw ScionHttp3Error.invalidRequest(detail: "a method cannot be empty")
            }
            if !rawValue.unicodeScalars.allSatisfy(ScionHttp3Headers.isToken) {
                throw ScionHttp3Error.invalidRequest(
                    detail: "\"\(rawValue)\" is not a method: expected a token, "
                        + "for example GET or POST")
            }
        }
    }

    /// The absolute URL to request.
    ///
    /// Must be `https`. This is an HTTP/3-only client with nothing to fall back to.
    public var url: String

    /// The method. If not set, defaults to `GET`.
    public var method: Method

    /// The header section. It does not include the `content-type` the body implies; that line is
    /// added when the request is sent, unless the section already has one.
    public var headers: ScionHttp3Headers

    /// The body or nil when the request sends none.
    public var body: ScionHttp3RequestBody?

    /// Addresses to send the request to instead of resolving the URL's host. Empty means resolve.
    ///
    /// Several addresses are raced as if resolution had returned them all.
    public var targets: [ScionAddress]

    /// Overrides the client's request timeout for this request.
    public var requestTimeout: TimeInterval?

    /// Overrides the client's response-body limit for this request.
    public var maxResponseBodyBytes: Int?

    /// Sends this request to one address instead of resolving the URL's host.
    public var target: ScionAddress? {
        get { targets.first }
        set { targets = newValue.map { [$0] } ?? [] }
    }

    public init(url: String, method: Method = .get, body: ScionHttp3RequestBody? = nil) {
        self.url = url
        self.method = method
        self.headers = ScionHttp3Headers()
        self.body = body
        self.targets = []
    }

    /// Throws `ScionHttp3Error.invalidRequest` for the first thing the stack cannot be given.
    func validate() throws {
        try Self.validateUrl(url)
        try method.validate()
        try headers.validate()
        if let requestTimeout, !(requestTimeout > 0) || !requestTimeout.isFinite {
            throw ScionHttp3Error.invalidRequest(
                detail: "a request timeout must be positive and finite, not \(requestTimeout) s")
        }
        if let maxResponseBodyBytes, maxResponseBodyBytes <= 0 {
            throw ScionHttp3Error.invalidRequest(
                detail: "a response body limit must be positive, not \(maxResponseBodyBytes) bytes")
        }
    }

    private static func validateUrl(_ url: String) throws {
        guard let components = URLComponents(string: url) else {
            throw ScionHttp3Error.invalidRequest(detail: "\"\(url)\" is not a valid URL")
        }
        guard let scheme = components.scheme else {
            throw ScionHttp3Error.invalidRequest(
                detail: "\"\(url)\" is not absolute: a request URL needs a scheme and a host")
        }
        if scheme.lowercased() != "https" {
            throw ScionHttp3Error.invalidRequest(
                detail: "\"\(url)\" is not https. This client speaks HTTP/3 over SCION only and "
                    + "has nothing to fall back to, so a plaintext URL cannot be served.")
        }
        if components.host?.isEmpty ?? true {
            throw ScionHttp3Error.invalidRequest(detail: "\"\(url)\" has no host")
        }
    }
}

extension ScionHttp3Request: CustomStringConvertible {
    public var description: String { "\(method) \(url)" }
}

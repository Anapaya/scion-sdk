// Copyright 2026 Anapaya Systems
import Foundation

/// A response body.
public final class ScionHttp3ResponseBody: Sendable {
    private let content: Data
    private let keepAlive: (any Sendable)?

    init(_ content: Data, keepAlive: (any Sendable)? = nil) {
        self.content = content
        self.keepAlive = keepAlive
    }

    /// How many bytes the body has.
    public var contentLength: Int { content.count }

    /// The bytes.
    ///
    /// Throws `ScionHttp3Error.bodyTooLarge` if the body is larger than `maxSize`.
    public func bytes(maxSize: Int = .max) async throws -> Data {
        try read(maxSize: maxSize)
    }

    /// The bytes decoded as UTF-8.
    ///
    /// Throws `ScionHttp3Error.invalidBody` if the body is not valid UTF-8, and
    /// `ScionHttp3Error.bodyTooLarge` if it is larger than `maxSize`.
    public func string(maxSize: Int = .max) async throws -> String {
        let bytes = try read(maxSize: maxSize)
        guard let string = String(data: bytes, encoding: .utf8) else {
            throw ScionHttp3Error.invalidBody(
                detail: "the response body is not valid UTF-8", retryable: false)
        }
        return string
    }

    private func read(maxSize: Int) throws -> Data {
        if content.count > maxSize {
            throw ScionHttp3Error.bodyTooLarge(
                limit: maxSize,
                detail: "the response body is \(content.count) bytes, over the \(maxSize) "
                    + "requested",
                retryable: false)
        }
        return content
    }
}

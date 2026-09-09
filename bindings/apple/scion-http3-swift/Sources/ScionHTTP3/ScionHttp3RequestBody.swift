// Copyright 2026 Anapaya Systems
import Foundation

/// The request body, if any, and its media type. The body is sent as-is; it is not encoded or
/// chunked.
public struct ScionHttp3RequestBody: Sendable, Equatable {
    /// The media type, sent as `content-type` unless the request already sets that header itself.
    /// Nil sends no `content-type` at all.
    public let contentType: String?

    /// The bytes.
    public let data: Data

    /// How many bytes are sent.
    public var contentLength: Int { data.count }

    public init(data: Data, contentType: String?) {
        self.data = data
        self.contentType = contentType
    }

    private static let jsonType = "application/json"
    private static let textType = "text/plain; charset=utf-8"

    /// UTF-8 encoded JSON, sent as `application/json`.
    public static func json(_ json: String) -> ScionHttp3RequestBody {
        text(json, contentType: jsonType)
    }

    /// Already-encoded JSON, sent as `application/json`.
    public static func json(_ json: Data) -> ScionHttp3RequestBody {
        bytes(json, contentType: jsonType)
    }

    /// UTF-8 encoded text, sent as `text/plain; charset=utf-8`.
    public static func text(_ text: String) -> ScionHttp3RequestBody {
        self.text(text, contentType: textType)
    }

    /// UTF-8 encoded text with a media type of your own.
    public static func text(_ text: String, contentType: String?) -> ScionHttp3RequestBody {
        ScionHttp3RequestBody(data: Data(text.utf8), contentType: contentType)
    }

    /// Arbitrary bytes, `application/octet-stream` unless another type is given.
    public static func bytes(
        _ bytes: Data, contentType: String? = "application/octet-stream"
    ) -> ScionHttp3RequestBody {
        ScionHttp3RequestBody(data: bytes, contentType: contentType)
    }

    /// A body of zero bytes and no media type.
    ///
    /// Not the same as sending no body: a `POST` with this body sends `content-length: 0`, where a
    /// request without a body sends no body at all.
    public static let empty = ScionHttp3RequestBody(data: Data(), contentType: nil)
}

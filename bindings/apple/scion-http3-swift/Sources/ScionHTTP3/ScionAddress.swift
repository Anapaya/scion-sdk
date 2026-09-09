// Copyright 2026 Anapaya Systems

/// A SCION address, for addressing a host directly instead of resolving its name.
///
/// The text form is `<isd>-<as>,<host>`, for example `1-ff00:0:110,10.0.0.1`. Only the shape is
/// checked here.
public struct ScionAddress: Sendable, Hashable, CustomStringConvertible {
    private let text: String

    /// Parses the `<isd>-<as>,<host>` form.
    ///
    /// Throws `ScionHttp3Error.invalidRequest` if `text` is not that shape, or carries a port.
    public init(_ text: String) throws {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            throw ScionHttp3Error.invalidRequest(detail: "a SCION address cannot be empty")
        }
        guard let comma = trimmed.firstIndex(of: ","), comma != trimmed.startIndex,
            trimmed.index(after: comma) != trimmed.endIndex
        else {
            throw ScionHttp3Error.invalidRequest(
                detail: "\"\(trimmed)\" is not a SCION address: expected <isd>-<as>,<host>, "
                    + "for example 1-ff00:0:110,10.0.0.1")
        }
        let isdAs = trimmed[..<comma]
        let dashes = isdAs.filter { $0 == "-" }.count
        if dashes != 1 || isdAs.hasPrefix("-") || isdAs.hasSuffix("-") {
            throw ScionHttp3Error.invalidRequest(
                detail: "\"\(isdAs)\" is not an ISD-AS: expected <isd>-<as>, "
                    + "for example 1-ff00:0:110")
        }
        let host = String(trimmed[trimmed.index(after: comma)...])
        try Self.requireNoPort(whole: trimmed, host: host)
        self.text = trimmed
    }

    public var description: String { text }

    private static func requireNoPort(whole: String, host: String) throws {
        let hasPort: Bool
        if host.hasPrefix("[") {
            // A bracketed IPv6 host: anything after the bracket can only be a port.
            guard let end = host.firstIndex(of: "]") else {
                throw ScionHttp3Error.invalidRequest(
                    detail: "\"\(host)\" opens a bracket it never closes")
            }
            hasPort = host.index(after: end) != host.endIndex
        } else {
            let colons = host.filter { $0 == ":" }.count
            let afterColon = host.split(separator: ":", omittingEmptySubsequences: false).last ?? ""
            hasPort =
                colons == 1 && !afterColon.isEmpty
                && afterColon.allSatisfy { $0.isASCII && $0.isNumber }
        }
        if hasPort {
            throw ScionHttp3Error.invalidRequest(
                detail: "\"\(whole)\" carries a port. A target addresses a host only; the port "
                    + "comes from the request URL.")
        }
    }
}

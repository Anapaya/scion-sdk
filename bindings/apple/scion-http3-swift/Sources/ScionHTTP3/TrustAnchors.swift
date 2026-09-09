// Copyright 2026 Anapaya Systems
import Foundation
import Security

/// Which certificate authorities a server's certificate is checked against.
///
/// The default is what an application wants unless it talks to a deployment with its own authority.
public struct TrustAnchors: Sendable, Equatable {
    enum Kind: Sendable, Equatable {
        case systemDefault
        case pinned(Data)
        case insecureNoVerify
    }

    let kind: Kind

    /// The system's own certificate authorities, the same set `URLSession` checks against.
    public static let systemDefault = TrustAnchors(kind: .systemDefault)

    /// Accepts any certificate
    ///
    /// A client built with this logs an error on every construction.
    public static let insecureNoVerify = TrustAnchors(kind: .insecureNoVerify)

    /// Exactly the authorities in `pem` and nothing the platform trusts.
    ///
    /// This is how to reach a private deployment whose certificates are signed by an internal
    /// authority. Pass one or more PEM `CERTIFICATE` blocks, concatenated.
    ///
    /// Throws `ScionHttp3Error.invalidConfiguration` if `pem` holds no certificate, or a block
    /// that is not one.
    public static func pinned(_ pem: Data) throws -> TrustAnchors {
        let certificates = try Self.certificates(in: pem)
        if certificates == 0 {
            throw ScionHttp3Error.invalidConfiguration(
                detail: "the trust anchors hold no certificate. Expected one or more PEM "
                    + "-----BEGIN CERTIFICATE----- blocks.")
        }
        // Passed on unchanged rather than re-encoded: a bundle's order is the caller's business.
        return TrustAnchors(kind: .pinned(pem))
    }

    private static let beginMarker = "-----BEGIN CERTIFICATE-----"
    private static let endMarker = "-----END CERTIFICATE-----"

    /// Counts the certificate blocks and fails on the first one that is not a certificate.
    private static func certificates(in pem: Data) throws -> Int {
        let text = String(decoding: pem, as: UTF8.self)
        var rest = text[...]
        var count = 0
        while let begin = rest.range(of: beginMarker) {
            let afterBegin = rest[begin.upperBound...]
            guard let end = afterBegin.range(of: endMarker) else {
                throw ScionHttp3Error.invalidConfiguration(
                    detail: "the trust anchors are not a readable PEM bundle: certificate "
                        + "\(count + 1) has no \(endMarker) line")
            }
            let base64 = String(afterBegin[..<end.lowerBound].filter { !$0.isWhitespace })
            guard let der = Data(base64Encoded: base64),
                SecCertificateCreateWithData(nil, der as CFData) != nil
            else {
                throw ScionHttp3Error.invalidConfiguration(
                    detail: "the trust anchors are not a readable PEM bundle: certificate "
                        + "\(count + 1) is not an X.509 certificate")
            }
            count += 1
            rest = afterBegin[end.upperBound...]
        }
        return count
    }
}

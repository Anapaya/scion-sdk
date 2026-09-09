// Copyright 2026 Anapaya Systems
import XCTest

@testable import ScionHTTP3

final class TrustAnchorsTests: XCTestCase {
    func testTheSystemDefaultIsTheStacksOwn() {
        XCTAssertEqual(ffiTrustAnchors(.systemDefault), .systemDefault)
    }

    func testPinnedAnchorsArePassedDownExactly() throws {
        let anchors = try TrustAnchors.pinned(validPem)
        XCTAssertEqual(ffiTrustAnchors(anchors), .pem(pem: validPem))
    }

    func testDisabledVerificationIsPassedDownAsSuch() {
        XCTAssertEqual(ffiTrustAnchors(.insecureNoVerify), .insecureNoVerify)
    }

    func testABundleWithNoCertificateIsRefusedAtTheCallThatSuppliedIt() {
        let error = thrown { try TrustAnchors.pinned(Data("not a bundle".utf8)) }
            as? ScionHttp3Error
        guard case .invalidConfiguration(let detail)? = error else {
            return XCTFail("\(String(describing: error))")
        }
        XCTAssertTrue(detail.contains("no certificate"), detail)
    }

    func testABlockThatIsNotACertificateIsRefused() {
        let pem = Data(
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".utf8)
        let error = thrown { try TrustAnchors.pinned(pem) } as? ScionHttp3Error
        XCTAssertTrue(error?.detail.contains("not an X.509 certificate") ?? false)

        let unterminated = Data("-----BEGIN CERTIFICATE-----\nAAAA\n".utf8)
        let unterminatedError = thrown { try TrustAnchors.pinned(unterminated) } as? ScionHttp3Error
        XCTAssertTrue(unterminatedError?.detail.contains("has no -----END") ?? false)
    }

    func testEveryBlockInABundleIsChecked() throws {
        var bundle = validPem
        bundle.append(validPem)
        XCTAssertNoThrow(try TrustAnchors.pinned(bundle))
        bundle.append(Data("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".utf8))
        XCTAssertNotNil(thrown { try TrustAnchors.pinned(bundle) })
    }

    func testDisablingVerificationIsLoud() throws {
        let log = RecordingLog()
        _ = try client(log: log, settings: settings(trust: .insecureNoVerify))
        XCTAssertEqual(log.errors.count, 1)
        XCTAssertTrue(log.errors[0].contains("DISABLED"))
    }

    func testOrdinaryAnchorsLogNothing() throws {
        let log = RecordingLog()
        _ = try client(log: log, settings: settings(trust: .systemDefault))
        _ = try client(log: log, settings: settings(trust: .pinned(validPem)))
        XCTAssertTrue(log.errors.isEmpty)
        XCTAssertTrue(log.warnings.isEmpty)
    }
}

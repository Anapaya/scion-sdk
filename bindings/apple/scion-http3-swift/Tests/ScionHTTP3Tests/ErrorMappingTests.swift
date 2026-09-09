// Copyright 2026 Anapaya Systems
import XCTest

@testable import ScionHTTP3

/// Every case the stack can report.
final class ErrorMappingTests: XCTestCase {
    /// Every FFI case with its counterpart. A new FFI case fails to compile in `publicError`, and
    /// belongs in this table as well.
    private let everyCase: [(ffi: FfiError, expected: ScionHttp3Error)] = [
        (.StackBuild(retryable: true, detail: "d1"), .connectivity(detail: "d1", retryable: true)),
        (.Resolution(host: "h", retryable: false, detail: "d2"),
         .resolution(host: "h", detail: "d2", retryable: false)),
        (.Connect(host: "h", port: 8443, retryable: true, detail: "d3"),
         .connect(host: "h", port: 8443, detail: "d3", retryable: true)),
        (.Tls(host: "h", retryable: false, detail: "d4"),
         .tls(host: "h", detail: "d4", retryable: false)),
        (.StreamReset(code: UInt64.max, retryable: true, detail: "d5"),
         .streamReset(code: UInt64.max, detail: "d5", retryable: true)),
        (.Protocol(retryable: false, detail: "d6"),
         .protocolViolation(detail: "d6", retryable: false)),
        (.ConnectionLimit(retryable: true, detail: "d7"),
         .connectionLimit(detail: "d7", retryable: true)),
        (.BodyTooLarge(limit: 1024, retryable: false, detail: "d8"),
         .bodyTooLarge(limit: 1024, detail: "d8", retryable: false)),
        (.Timeout(phase: .request, timeoutMs: 1_500, retryable: true, detail: "d9"),
         .timeout(phase: .request, after: 1.5, detail: "d9", retryable: true)),
        (.InvalidRequest(retryable: false, detail: "d10"), .invalidRequest(detail: "d10")),
        (.Closed(retryable: false, detail: "d11"), .closed),
        (.Internal(retryable: false, detail: "d12"), .internalError(detail: "d12")),
    ]

    func testEveryCaseMapsToItsCounterpart() {
        for (ffi, expected) in everyCase {
            XCTAssertEqual(publicError(ffi) as? ScionHttp3Error, expected, "\(ffi)")
        }
    }

    func testACancellationBecomesSwiftsOwnError() {
        let error = publicError(FfiError.Cancelled(retryable: false, detail: "cancelled"))
        XCTAssertTrue(error is CancellationError, "\(error)")
    }

    func testOtherErrorsPassThroughUnchanged() {
        XCTAssertTrue(publicError(CancellationError()) is CancellationError)
        XCTAssertEqual(publicError(ScionHttp3Error.closed) as? ScionHttp3Error, .closed)
    }

    func testRetryabilityAndDetailComeFromTheStackNotTheCase() {
        let retryable = publicError(
            FfiError.Connect(host: "h", port: 1, retryable: true, detail: "a"))
        let final = publicError(FfiError.Connect(host: "h", port: 1, retryable: false, detail: "b"))
        XCTAssertEqual((retryable as? ScionHttp3Error)?.isRetryable, true)
        XCTAssertEqual((final as? ScionHttp3Error)?.isRetryable, false)
        XCTAssertEqual((final as? ScionHttp3Error)?.detail, "b")
    }

    func testEveryTimeoutPhaseHasACounterpart() {
        let phases: [(FfiTimeoutPhase, ScionHttp3Error.TimeoutPhase)] = [
            (.connect, .connect), (.request, .request), (.body, .body), (.other, .other),
        ]
        for (ffi, expected) in phases {
            let error = publicError(
                FfiError.Timeout(phase: ffi, timeoutMs: 1, retryable: true, detail: ""))
            guard case .timeout(let phase, _, _, _)? = error as? ScionHttp3Error else {
                return XCTFail("\(error)")
            }
            XCTAssertEqual(phase, expected)
        }
    }

    func testDescriptionsSaySomethingUseful() {
        XCTAssertEqual(
            ScionHttp3Error.connect(host: "h", port: 443, detail: "refused", retryable: true)
                .localizedDescription,
            "h:443: refused")
        XCTAssertEqual(
            ScionHttp3Error.bodyTooLarge(limit: 10, detail: "x", retryable: false)
                .localizedDescription,
            "response body exceeds 10 bytes")
        XCTAssertTrue(ScionHttp3Error.closed.localizedDescription.contains("shut down"))
        XCTAssertTrue(
            ScionHttp3Error.timeout(phase: .connect, after: 0.5, detail: "x", retryable: true)
                .localizedDescription.contains("connect"))
    }

    func testTheCasesWithoutARetryableFieldAreNeverRetryable() {
        XCTAssertFalse(ScionHttp3Error.invalidRequest(detail: "").isRetryable)
        XCTAssertFalse(ScionHttp3Error.invalidConfiguration(detail: "").isRetryable)
        XCTAssertFalse(ScionHttp3Error.closed.isRetryable)
        XCTAssertFalse(ScionHttp3Error.internalError(detail: "").isRetryable)
    }
}

// Copyright 2026 Anapaya Systems
import XCTest

@testable import ScionHTTP3

final class HeadersTests: XCTestCase {
    func testLookupIsCaseInsensitiveAndReturnsTheFirstValue() {
        let headers = ScionHttp3Headers(["Set-Cookie": "a=1", "set-cookie": "b=2"])
        XCTAssertEqual(headers["SET-COOKIE"], "a=1")
        XCTAssertTrue(headers.contains("Set-Cookie"))
        XCTAssertNil(headers["accept"])
    }

    func testRepetitionIsPreservedInOrder() {
        let headers = ScionHttp3Headers(["set-cookie": "a=1", "accept": "*/*", "Set-Cookie": "b=2"])
        XCTAssertEqual(headers.values("set-cookie"), ["a=1", "b=2"])
        XCTAssertEqual(headers.map(\.value), ["a=1", "*/*", "b=2"])
        XCTAssertEqual(headers.count, 3)
    }

    func testSetReplacesEveryLineWithTheName() {
        var headers = ScionHttp3Headers(["set-cookie": "a=1", "accept": "*/*", "Set-Cookie": "b=2"])
        headers.set("SET-COOKIE", "c=3")
        XCTAssertEqual(headers.values("set-cookie"), ["c=3"])
        XCTAssertEqual(headers.map(\.name), ["accept", "SET-COOKIE"])
    }

    func testRemoveAllIsCaseInsensitive() {
        var headers = ScionHttp3Headers(["Accept": "*/*", "accept": "text/plain", "x-a": "1"])
        headers.removeAll("ACCEPT")
        XCTAssertEqual(headers.map(\.name), ["x-a"])
    }

    func testNamesAreDistinctLowerCasedAndInOrderOfFirstAppearance() {
        let headers = ScionHttp3Headers(["B": "1", "a": "2", "b": "3"])
        XCTAssertEqual(headers.names, ["b", "a"])
    }

    func testACopyLeavesTheOriginalAlone() {
        let original = ScionHttp3Headers(["a": "1"])
        var copy = original
        copy.add("b", "2")
        XCTAssertEqual(original.count, 1)
        XCTAssertEqual(copy.count, 2)
    }

    func testAnInvalidNameIsRefusedWhenValidated() {
        var headers = ScionHttp3Headers()
        headers.add("bad name", "1")
        let error = thrown { try headers.validate() } as? ScionHttp3Error
        guard case .invalidRequest(let detail)? = error else {
            return XCTFail("\(String(describing: error))")
        }
        XCTAssertTrue(detail.contains("U+0020"), detail)

        headers = ScionHttp3Headers([" ": "1"])
        XCTAssertNotNil(thrown { try headers.validate() })
        headers = ScionHttp3Headers(["": "1"])
        XCTAssertNotNil(thrown { try headers.validate() })
    }

    func testAnInvalidValueIsRefusedWhenValidated() {
        let cases = [
            ("a\nb", "a line feed"), ("a\rb", "a carriage return"), ("caf\u{E9}", "U+00E9"),
            ("\u{7F}", "a DEL"),
        ]
        for (value, expected) in cases {
            let headers = ScionHttp3Headers(["x-a": value])
            let error = thrown { try headers.validate() } as? ScionHttp3Error
            XCTAssertTrue(error?.detail.contains(expected) ?? false, "\(String(describing: error))")
        }
    }

    func testTokenSymbolsAndTabsAreAllowed() {
        let headers = ScionHttp3Headers(["x-token!#$%&'*+-.^_`|~": "tab\there ~"])
        XCTAssertNoThrow(try headers.validate())
    }

    func testStructuralEquality() {
        XCTAssertEqual(ScionHttp3Headers(["a": "1"]), ScionHttp3Headers(["a": "1"]))
        XCTAssertNotEqual(ScionHttp3Headers(["a": "1"]), ScionHttp3Headers(["A": "1"]))
    }

    func testDescription() {
        XCTAssertEqual(ScionHttp3Headers(["a": "1", "b": "2"]).description, "a: 1, b: 2")
        XCTAssertTrue(ScionHttp3Headers().isEmpty)
    }
}

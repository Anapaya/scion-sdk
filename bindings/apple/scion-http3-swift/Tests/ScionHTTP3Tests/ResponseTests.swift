// Copyright 2026 Anapaya Systems
import XCTest

@testable import ScionHTTP3

final class ResponseTests: XCTestCase {
    private func response(
        status: UInt16 = 200, headers: [FfiHeader] = [], body: Data = Data(),
        trailers: [FfiHeader] = []
    ) -> ScionHttp3Response {
        publicResponse(
            from: fakeResponse(status: status, headers: headers, body: body, trailers: trailers),
            to: request(), keepAlive: 0)
    }

    func testANon2xxStatusIsAResponse() {
        let response = response(status: 404)
        XCTAssertEqual(response.code, 404)
        XCTAssertFalse(response.isSuccessful)
        XCTAssertTrue(self.response(status: 204).isSuccessful)
    }

    func testAbsentAndEmptyTrailersAreDifferent() {
        XCTAssertNil(response().trailers, "the stack reports no trailer section as an empty list")
        XCTAssertEqual(
            response(trailers: [FfiHeader(name: "x-checksum", value: "42")])
                .trailers?["x-checksum"],
            "42")
    }

    func testBytesAndText() async throws {
        let body = response(body: Data("world".utf8)).body
        XCTAssertEqual(body.contentLength, 5)
        let bytes = try await body.bytes()
        let string = try await body.string()
        XCTAssertEqual(bytes, Data("world".utf8))
        XCTAssertEqual(string, "world")
    }

    func testABodyThatIsNotUtf8FailsAsTextAndReadsAsBytes() async throws {
        let body = response(body: Data([0xFF, 0xFE])).body
        let error = await thrown { try await body.string() } as? ScionHttp3Error
        guard case .invalidBody(_, let retryable)? = error else {
            return XCTFail("\(String(describing: error))")
        }
        XCTAssertFalse(retryable)
        let bytes = try await body.bytes()
        XCTAssertEqual(bytes, Data([0xFF, 0xFE]))
    }

    func testABodyOverTheRequestedSizeIsRefused() async throws {
        let body = response(body: Data(repeating: 0x78, count: 10)).body
        let error = await thrown { try await body.bytes(maxSize: 9) } as? ScionHttp3Error
        guard case .bodyTooLarge(let limit, _, let retryable)? = error else {
            return XCTFail("\(String(describing: error))")
        }
        XCTAssertEqual(limit, 9)
        XCTAssertFalse(retryable)
        let exact = try await body.bytes(maxSize: 10)
        XCTAssertEqual(exact.count, 10)
    }

    func testResponseHeadersKeepOrderAndRepetition() {
        let headers = response(headers: [
            FfiHeader(name: "set-cookie", value: "a=1"),
            FfiHeader(name: "set-cookie", value: "b=2"),
        ]).headers
        XCTAssertEqual(headers.values("set-cookie"), ["a=1", "b=2"])
    }

    func testAResponseKnowsItsRequest() {
        let response = response()
        XCTAssertEqual(response.request, request())
        XCTAssertEqual(response.description, "200 GET https://example.org/hello")
    }
}

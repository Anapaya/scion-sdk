// Copyright 2026 Anapaya Systems
import XCTest

@testable import ScionHTTP3

/// The request as the stack receives it, and what is refused before it gets there.
final class RequestMappingTests: XCTestCase {
    func testNoBodyAndAnEmptyBodyAreDifferent() throws {
        XCTAssertNil(try ffiRequest(from: request()).body)

        var withEmptyBody = request()
        withEmptyBody.method = .post
        withEmptyBody.body = .empty
        XCTAssertEqual(try ffiRequest(from: withEmptyBody).body, Data())
    }

    func testHeaderOrderAndRepetitionSurvive() throws {
        var request = request()
        request.headers.add("x-a", "1")
        request.headers.add("accept", "*/*")
        request.headers.add("X-A", "2")
        let headers = try ffiRequest(from: request).headers
        XCTAssertEqual(headers.map(\.name), ["x-a", "accept", "X-A"])
        XCTAssertEqual(headers.map(\.value), ["1", "*/*", "2"])
    }

    func testTheBodysMediaTypeIsSentUnlessTheCallerSetOne() throws {
        var request = request()
        request.method = .post
        request.body = .json("{}")
        XCTAssertEqual(
            try ffiRequest(from: request).headers.first { $0.name == "content-type" }?.value,
            "application/json")

        request.headers.set("Content-Type", "application/problem+json")
        let headers = try ffiRequest(from: request).headers
        XCTAssertEqual(headers.filter { $0.name.lowercased() == "content-type" }.count, 1)
        XCTAssertEqual(
            headers.first { $0.name == "Content-Type" }?.value, "application/problem+json")

        request.headers = ScionHttp3Headers()
        request.body = .empty
        XCTAssertFalse(try ffiRequest(from: request).headers.contains { $0.name == "content-type" })
    }

    func testTheMediaTypeDoesNotLeakIntoTheValue() throws {
        var request = request()
        request.body = .json("{}")
        _ = try ffiRequest(from: request)
        _ = try ffiRequest(from: request)
        XCTAssertTrue(request.headers.isEmpty, "the value itself stays as the caller wrote it")
    }

    func testTargetsCrossAsTextWithoutPorts() throws {
        var request = request()
        request.target = try ScionAddress("1-ff00:0:110,10.0.0.1")
        XCTAssertEqual(try ffiRequest(from: request).targets, ["1-ff00:0:110,10.0.0.1"])

        request.targets = [
            try ScionAddress("1-ff00:0:110,10.0.0.1"), try ScionAddress("1-ff00:0:110,10.0.0.2"),
        ]
        XCTAssertEqual(try ffiRequest(from: request).targets.count, 2)
        XCTAssertEqual(request.target?.description, "1-ff00:0:110,10.0.0.1")

        request.target = nil
        XCTAssertTrue(request.targets.isEmpty)
    }

    func testOverridesAreAbsentUnlessSet() throws {
        let plain = try ffiRequest(from: request())
        XCTAssertNil(plain.requestTimeoutMs)
        XCTAssertNil(plain.maxResponseBodyBytes)

        var request = request()
        request.requestTimeout = 2.5
        request.maxResponseBodyBytes = 1024
        let mapped = try ffiRequest(from: request)
        XCTAssertEqual(mapped.requestTimeoutMs, 2_500)
        XCTAssertEqual(mapped.maxResponseBodyBytes, 1024)
    }

    func testTheMethodIsSentVerbatim() throws {
        var request = request()
        request.method = "Purge"
        XCTAssertEqual(try ffiRequest(from: request).method, "Purge")
        request.method = .delete
        XCTAssertEqual(try ffiRequest(from: request).method, "DELETE")
    }

    func testAPlaintextUrlIsRefused() {
        let error = thrown { try ffiRequest(from: request("http://example.org/")) }
        guard case .invalidRequest(let detail)? = error as? ScionHttp3Error else {
            return XCTFail("\(String(describing: error))")
        }
        XCTAssertTrue(detail.contains("not https"), detail)
    }

    func testAUrlWithoutSchemeOrHostIsRefused() {
        for url in ["/relative", "https://", "https:///path", "not a url at all ://"] {
            let error = thrown { try ffiRequest(from: request(url)) }
            XCTAssertTrue(error is ScionHttp3Error, "\(url) was accepted")
        }
    }

    func testAMethodThatIsNotATokenIsRefused() {
        var request = request()
        request.method = "not a method"
        let error = thrown { try ffiRequest(from: request) } as? ScionHttp3Error
        XCTAssertTrue(error?.detail.contains("is not a method") ?? false)
        request.method = ""
        XCTAssertNotNil(thrown { try ffiRequest(from: request) })
    }

    func testABadHeaderIsRefusedBeforeAnythingIsSent() {
        var request = request()
        request.headers.add("x-a", "line\nbreak")
        let error = thrown { try ffiRequest(from: request) } as? ScionHttp3Error
        guard case .invalidRequest? = error else { return XCTFail("\(String(describing: error))") }
    }

    func testANonPositiveOverrideIsRefused() {
        var request = request()
        request.requestTimeout = 0
        XCTAssertNotNil(thrown { try ffiRequest(from: request) })
        request.requestTimeout = .infinity
        XCTAssertNotNil(thrown { try ffiRequest(from: request) })
        request.requestTimeout = 1
        request.maxResponseBodyBytes = 0
        XCTAssertNotNil(thrown { try ffiRequest(from: request) })
    }

    func testTheSameValueCanBeSentTwice() async throws {
        let factory = FakeBackendFactory()
        let client = try client(factory: factory)
        let request = request()
        _ = try await client.execute(request)
        _ = try await client.execute(request)
        XCTAssertEqual(factory.backend.requests.count, 2)
    }

    func testTheShorthandsSendWhatTheLongFormSends() async throws {
        let factory = FakeBackendFactory()
        let client = try client(factory: factory)
        _ = try await client.get("https://example.org/rooms")
        _ = try await client.post("https://example.org/rooms", body: .json("{}"))
        let requests = factory.backend.requests
        XCTAssertEqual(requests.map(\.method), ["GET", "POST"])
        XCTAssertEqual(requests[1].body, Data("{}".utf8))
        XCTAssertEqual(requests[1].headers.first?.name, "content-type")
    }

    func testDescription() {
        var request = request("https://example.org/x")
        request.method = .post
        XCTAssertEqual(request.description, "POST https://example.org/x")
    }
}

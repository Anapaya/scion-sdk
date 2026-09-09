// Copyright 2026 Anapaya Systems
import XCTest

@testable import ScionHTTP3

/// Whole situations, over the fakes: what an application sees across a network change.
final class ScenarioTests: XCTestCase {
    private let factory = FakeBackendFactory()
    private let monitor = FakeNetworkMonitor(current: identity())
    private let clock = FakeClock()

    private func connectedClient() async throws -> ScionHttp3Client {
        let client = try client(factory: factory, monitor: monitor, clock: clock)
        _ = try await client.execute(request())
        monitor.observe(identity())
        return client
    }

    func testAnApplicationResumedOnAnotherNetworkRebuildsOnceThenSucceeds() async throws {
        let client = try await connectedClient()
        clock.advance(10)

        monitor.observe(identity(interfaceName: "pdp_ip0", interfaceType: "cellular", gateways: []))
        let first = try await client.execute(request())
        let second = try await client.execute(request())

        XCTAssertEqual(first.code, 200)
        XCTAssertEqual(second.code, 200)
        XCTAssertEqual(factory.backend.resets, 1, "one change, one rebuild")
        XCTAssertEqual(factory.backend.requests.count, 3)
    }

    func testAManualResetIsNotRepeatedByTheNextRequest() async throws {
        let client = try await connectedClient()

        client.reset()
        _ = try await client.execute(request())

        XCTAssertEqual(factory.backend.resets, 1)
    }

    func testALongIdleApplicationChecksTheNetworkItselfAndRebuildsWhenItMoved() async throws {
        let client = try await connectedClient()

        clock.advance(60)
        _ = try await client.execute(request())
        XCTAssertEqual(factory.backend.resets, 0, "the same path is still the same path")

        monitor.current = identity(
            interfaceName: "pdp_ip0", interfaceType: "cellular", gateways: [])
        clock.advance(60)
        _ = try await client.execute(request())
        XCTAssertEqual(factory.backend.resets, 1, "no update arrived; the check caught the move")
    }

    func testABriefLossThatRecoversOntoTheSameNetworkCostsNothing() async throws {
        let client = try await connectedClient()
        clock.advance(10)

        monitor.observe(identity(satisfied: false))
        clock.advance(0.1)
        monitor.observe(identity(interfaceName: "pdp_ip0", interfaceType: "cellular", gateways: []))
        monitor.observe(identity())
        clock.advance(10)
        _ = try await client.execute(request())

        XCTAssertEqual(factory.backend.resets, 0)
    }

    func testABodyReadsAsTextThroughTheShorthand() async throws {
        factory.backend.response.withLock { $0 = fakeResponse(body: Data("world".utf8)) }
        let client = try client(factory: factory, monitor: monitor, clock: clock)

        let text = try await client.get("https://example.org/hello").body.string()

        XCTAssertEqual(text, "world")
    }
}

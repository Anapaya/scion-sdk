// Copyright 2026 Anapaya Systems
import XCTest

@testable import ScionHTTP3

/// The properties whose absence is a crash or a hang rather than a wrong answer.
final class LifecycleTests: XCTestCase {
    func testShutdownIsIdempotentAndReleasesEverythingOnce() async throws {
        let factory = FakeBackendFactory()
        let monitor = FakeNetworkMonitor()
        let client = try client(factory: factory, monitor: monitor)
        _ = try await client.execute(request())

        await client.shutdown()
        await client.shutdown()

        XCTAssertTrue(client.isShutDown)
        XCTAssertEqual(factory.backend.shutdowns, 1)
        XCTAssertEqual(monitor.stops, 1, "stopped once, however often shutdown runs")
    }

    func testShuttingDownAnUnusedClientBuildsNothing() async throws {
        let factory = FakeBackendFactory()
        let client = try client(factory: factory)

        await client.shutdown()

        XCTAssertEqual(factory.creations.withLock { $0 }, 0)
        XCTAssertEqual(factory.backend.shutdowns, 0)
    }

    func testARequestAfterShutdownFailsAsClosedWithoutTouchingTheBackend() async throws {
        let factory = FakeBackendFactory()
        let client = try client(factory: factory)
        await client.shutdown()

        let error = await thrown { try await client.execute(request()) } as? ScionHttp3Error
        XCTAssertEqual(error, .closed)
        XCTAssertFalse(error?.isRetryable ?? true)
        XCTAssertEqual(factory.creations.withLock { $0 }, 0)

        let warmUpError = await thrown { try await client.warmUp("https://example.org") }
        XCTAssertEqual(warmUpError as? ScionHttp3Error, .closed)
    }

    func testABackendBuiltWhileShutdownRanIsShutDownRatherThanPublished() async throws {
        let factory = FakeBackendFactory()
        let monitor = FakeNetworkMonitor()
        let holdCreation = Hold()
        factory.whileCreating.withLock { $0 = { holdCreation.wait() } }
        let client = try client(factory: factory, monitor: monitor)

        let task = Task { try await client.execute(request()) }
        let creating = await eventually { factory.creations.withLock { $0 } == 1 }
        XCTAssertTrue(creating)
        await client.shutdown()
        holdCreation.release()

        let result = await task.result
        guard case .failure(let error) = result else { return XCTFail("the request completed") }
        XCTAssertEqual(error as? ScionHttp3Error, .closed)
        XCTAssertEqual(factory.backend.shutdowns, 1, "the backend was released by exactly one side")
        XCTAssertEqual(factory.backend.requests.count, 0)
        XCTAssertGreaterThanOrEqual(monitor.stops, 1)
    }

    func testConcurrentFirstRequestsShareOneConstruction() async throws {
        let factory = FakeBackendFactory()
        let holdCreation = Hold()
        factory.whileCreating.withLock { $0 = { holdCreation.wait() } }
        let client = try client(factory: factory)

        let tasks = (0..<5).map { _ in Task { try await client.execute(request()) } }
        _ = await eventually { factory.creations.withLock { $0 } == 1 }
        holdCreation.release()
        for task in tasks {
            _ = try await task.value
        }

        XCTAssertEqual(factory.creations.withLock { $0 }, 1)
        XCTAssertEqual(factory.backend.requests.count, 5)
    }

    func testAConstructionFailureSurfacesAsThisLibrarysErrorAndIsNotRemembered() async throws {
        let factory = FakeBackendFactory()
        factory.failure.withLock {
            $0 = FfiError.InvalidRequest(retryable: false, detail: "bad ip")
        }
        let client = try client(factory: factory)

        let error = await thrown { try await client.execute(request()) } as? ScionHttp3Error
        XCTAssertEqual(error, .invalidRequest(detail: "bad ip"))

        factory.failure.withLock { $0 = nil }
        _ = try await client.execute(request())
        XCTAssertEqual(factory.creations.withLock { $0 }, 2, "the failure was not cached")
    }

    func testAStackFailureArrivesAsThisLibrarysError() async throws {
        let factory = FakeBackendFactory()
        factory.backend.failure.withLock {
            $0 = FfiError.Timeout(phase: .connect, timeoutMs: 500, retryable: true, detail: "slow")
        }
        let client = try client(factory: factory)

        let error = await thrown { try await client.execute(request()) } as? ScionHttp3Error
        XCTAssertEqual(
            error, .timeout(phase: .connect, after: 0.5, detail: "slow", retryable: true))
    }

    func testARenewedTokenReachesTheStack() async throws {
        let factory = FakeBackendFactory()
        let client = try client(factory: factory, settings: settings(authToken: "t1"))
        _ = try await client.execute(request())

        try client.setAuthToken("t2")

        XCTAssertEqual(factory.backend.tokens, ["t2"])
    }

    func testATokenRenewedBeforeTheFirstRequestIsNotLost() async throws {
        let factory = FakeBackendFactory()
        let client = try client(factory: factory, settings: settings(authToken: "t1"))

        try client.setAuthToken("t2")
        _ = try await client.execute(request())

        XCTAssertEqual(factory.backend.tokens, ["t2"])
    }

    func testTheConfiguredTokenIsNotReplayedOntoAFreshStack() async throws {
        let factory = FakeBackendFactory()
        let client = try client(factory: factory, settings: settings(authToken: "t1"))

        try client.setAuthToken("t1")
        _ = try await client.execute(request())

        XCTAssertTrue(factory.backend.tokens.isEmpty, "the stack was built with that token already")
    }

    func testARenewalOnAShutDownClientIsIgnored() async throws {
        let factory = FakeBackendFactory()
        let log = RecordingLog()
        let client = try client(factory: factory, log: log, settings: settings(authToken: "t1"))
        _ = try await client.execute(request())
        await client.shutdown()

        try client.setAuthToken("t2")

        XCTAssertTrue(factory.backend.tokens.isEmpty)
        XCTAssertTrue(log.debugs.contains { $0.contains("token renewal") })
    }

    func testARenewalWithoutAConfiguredTokenIsRefused() throws {
        let client = try client()
        let error = thrown { try client.setAuthToken("t2") } as? ScionHttp3Error
        guard case .invalidConfiguration(let detail)? = error else {
            return XCTFail("\(String(describing: error))")
        }
        XCTAssertTrue(detail.contains("without an authToken"), detail)
    }

    func testAnEmptyTokenIsRefused() throws {
        let client = try client(settings: settings(authToken: "t1"))
        XCTAssertNotNil(thrown { try client.setAuthToken("") })
    }

    func testAFailedRenewalArrivesAsThisLibrarysError() async throws {
        let factory = FakeBackendFactory()
        factory.backend.setAuthTokenFailure.withLock {
            $0 = FfiError.InvalidRequest(retryable: false, detail: "no token source")
        }
        let client = try client(factory: factory, settings: settings(authToken: "t1"))
        _ = try await client.execute(request())

        let error = thrown { try client.setAuthToken("t2") } as? ScionHttp3Error
        XCTAssertEqual(error, .invalidRequest(detail: "no token source"))
    }

    func testABackendWhoseTokenCatchUpFailsIsShutDown() async throws {
        let factory = FakeBackendFactory()
        factory.backend.setAuthTokenFailure.withLock {
            $0 = FfiError.Internal(retryable: false, detail: "boom")
        }
        let client = try client(factory: factory, settings: settings(authToken: "t1"))
        try client.setAuthToken("t2")

        let error = await thrown { try await client.execute(request()) } as? ScionHttp3Error
        XCTAssertEqual(error, .internalError(detail: "boom"))
        XCTAssertEqual(factory.backend.shutdowns, 1, "connections would leak otherwise")
    }

    func testResetBeforeTheFirstRequestDoesNothing() throws {
        let factory = FakeBackendFactory()
        let client = try client(factory: factory)

        client.reset()

        XCTAssertEqual(factory.creations.withLock { $0 }, 0)
        XCTAssertEqual(factory.backend.resets, 0)
    }

    func testResetReachesTheBackendAndIsIgnoredOnceShutDown() async throws {
        let factory = FakeBackendFactory()
        let client = try client(factory: factory)
        _ = try await client.execute(request())

        client.reset()
        XCTAssertEqual(factory.backend.resets, 1)

        await client.shutdown()
        client.reset()
        XCTAssertEqual(factory.backend.resets, 1)
    }

    func testWarmUpReachesTheBackendAndRebuildsStaleConnectivityLikeARequest() async throws {
        let factory = FakeBackendFactory()
        let monitor = FakeNetworkMonitor()
        let clock = FakeClock()
        let client = try client(factory: factory, monitor: monitor, clock: clock)
        try await client.warmUp("https://example.org")
        XCTAssertEqual(factory.backend.warmedUp, ["https://example.org"])

        monitor.observe(identity())
        clock.advance(10)
        monitor.observe(identity(interfaceName: "pdp_ip0", interfaceType: "cellular"))
        try await client.warmUp("https://example.org")

        XCTAssertEqual(factory.backend.resets, 1)
    }

    func testANetworkObservationAfterShutdownNeitherResetsNorCrashes() async throws {
        let factory = FakeBackendFactory()
        let monitor = FakeNetworkMonitor()
        let clock = FakeClock()
        let client = try client(factory: factory, monitor: monitor, clock: clock)
        _ = try await client.execute(request())
        monitor.observe(identity())
        await client.shutdown()

        clock.advance(10)
        monitor.observe(identity(interfaceName: "pdp_ip0", interfaceType: "cellular"))

        XCTAssertEqual(factory.backend.resets, 0)
    }
}

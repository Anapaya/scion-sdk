// Copyright 2026 Anapaya Systems
import XCTest

@testable import ScionHTTP3

/// The plumbing between a cancelled `Task` and the handle the stack watches.
final class CancellationTests: XCTestCase {
    func testCancellingTheTaskFiresTheHandleAndThrowsCancellationError() async throws {
        let factory = FakeBackendFactory()
        let gate = Gate()
        factory.backend.gate.withLock { $0 = gate }
        let client = try client(factory: factory)

        let task = Task { try await client.execute(request()) }
        let started = await eventually { factory.backend.requests.count == 1 }
        XCTAssertTrue(started, "the request never reached the backend")

        task.cancel()
        let result = await task.result
        guard case .failure(let error) = result else { return XCTFail("the request completed") }
        XCTAssertTrue(error is CancellationError, "\(error)")
        XCTAssertTrue(factory.backend.executeWasCancelled, "the handle did not fire")
        XCTAssertEqual(factory.backend.handles.count, 1)
        XCTAssertTrue(factory.backend.handles[0].isFired)
    }

    func testATaskCancelledBeforeTheCallFiresTheHandleFirst() async throws {
        let factory = FakeBackendFactory()
        let client = try client(factory: factory)

        let task = Task { try await client.execute(request()) }
        task.cancel()

        let result = await task.result
        guard case .failure(let error) = result else { return XCTFail("the request completed") }
        XCTAssertTrue(error is CancellationError, "\(error)")
        XCTAssertTrue(factory.backend.handles.allSatisfy(\.isFired))
    }

    func testAHandleThatNeverFiresDeliversTheResponse() async throws {
        let factory = FakeBackendFactory()
        let client = try client(factory: factory)

        let response = try await client.execute(request())

        XCTAssertEqual(response.code, 200)
        XCTAssertEqual(factory.backend.handles.count, 1)
        XCTAssertFalse(factory.backend.handles[0].isFired)
    }

    func testEveryRequestGetsAHandleOfItsOwn() async throws {
        let factory = FakeBackendFactory()
        let client = try client(factory: factory)

        _ = try await client.execute(request())
        _ = try await client.execute(request())

        let handles = factory.backend.handles
        XCTAssertEqual(handles.count, 2)
        XCTAssertFalse(handles[0] === handles[1])
    }

    func testTheStacksCancelledAnswerNeverSurfacesAsALibraryError() async throws {
        // A stack that reports a cancellation nobody asked for: still not a ScionHttp3Error,
        // because the caller who holds the task is the only one who can have cancelled it.
        let factory = FakeBackendFactory()
        factory.backend.failure.withLock {
            $0 = FfiError.Cancelled(retryable: false, detail: "the request was cancelled")
        }
        let client = try client(factory: factory)

        let error = await thrown { try await client.execute(request()) }
        XCTAssertTrue(error is CancellationError, "\(String(describing: error))")
    }

    func testACancelledRequestStillEndsTheUseForTheIdleCheck() async throws {
        let factory = FakeBackendFactory()
        let gate = Gate()
        factory.backend.gate.withLock { $0 = gate }
        let clock = FakeClock()
        let monitor = FakeNetworkMonitor(current: identity())
        let client = try client(factory: factory, monitor: monitor, clock: clock)

        let task = Task { try await client.execute(request()) }
        _ = await eventually { factory.backend.requests.count == 1 }
        clock.advance(60)
        task.cancel()
        _ = await task.result

        factory.backend.gate.withLock { $0 = nil }
        clock.advance(10)
        _ = try await client.execute(request())
        XCTAssertEqual(factory.backend.resets, 0, "the gap is measured from the request's end")
    }
}

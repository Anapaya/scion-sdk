// Copyright 2026 Anapaya Systems
import XCTest

@testable import ScionHTTP3

/// The rules that decide when connectivity is rebuilt.
final class StalenessTests: XCTestCase {
    private let clock = FakeClock()
    private let log = RecordingLog()

    private func tracker(idleThreshold: TimeInterval = 50) -> StalenessTracker {
        StalenessTracker(clock: clock, idleThreshold: idleThreshold, log: log)
    }

    private func use(_ tracker: StalenessTracker, probe: () -> NetworkIdentity? = { nil }) -> Bool {
        tracker.onUseAttempt(probe: probe)
    }

    func testAFreshClientIsNotStale() {
        let tracker = tracker()
        XCTAssertFalse(use(tracker), "nothing has changed yet, so there is nothing to rebuild")
    }

    func testTheFirstObservationIsAdoptedWithoutMarkingAnythingStale() {
        let tracker = tracker()

        tracker.observe(identity())

        XCTAssertEqual(tracker.pathInUse, identity())
        XCTAssertFalse(
            use(tracker),
            "starting a monitor reports the current path at once, and a client that has not "
                + "connected yet has nothing stale about it")
    }

    func testAPathThatIsNotSatisfiedIsIgnored() {
        let tracker = tracker()
        tracker.observe(identity(interfaceName: "en0"))

        tracker.observe(
            identity(interfaceName: "pdp_ip0", interfaceType: "cellular", satisfied: false))
        tracker.observe(identity(interfaceName: nil, interfaceType: nil, gateways: []))

        XCTAssertFalse(use(tracker), "a path is reported before it can carry anything")
        XCTAssertEqual(tracker.pathInUse?.interfaceName, "en0")
    }

    func testASatisfiedChangeToAnotherPathMarksStaleOnce() {
        let tracker = tracker()
        tracker.observe(identity())
        clock.advance(10)

        tracker.observe(identity(interfaceName: "pdp_ip0", interfaceType: "cellular", gateways: []))

        XCTAssertTrue(use(tracker), "the first request after a change rebuilds")
        XCTAssertFalse(use(tracker), "the second does not, because the first already did")
    }

    func testCapabilityChurnOnTheSamePathChangesNothing() {
        let tracker = tracker()
        tracker.observe(identity())
        clock.advance(10)

        for _ in 0..<5 {
            tracker.observe(identity())
        }

        XCTAssertFalse(
            use(tracker), "expensive and constrained flip constantly and mean nothing here")
    }

    func testAGatewayChangeOnTheSameInterfaceMarksStale() {
        let tracker = tracker()
        tracker.observe(identity(gateways: ["192.168.1.1"]))
        clock.advance(10)

        tracker.observe(identity(gateways: ["10.0.0.1"]))

        XCTAssertTrue(
            use(tracker),
            "a move between two Wi-Fi networks keeps the interface name, and the new gateway is "
                + "what says the sockets underneath are gone")
    }

    func testAChangeBackToThePathInUseCancelsARememberedChange() {
        let tracker = tracker()
        let home = identity()
        tracker.observe(home)

        // Inside the debounce window, so this is remembered rather than acted on.
        clock.advance(0.1)
        tracker.observe(identity(interfaceName: "pdp_ip0", interfaceType: "cellular"))
        tracker.observe(home)

        clock.advance(10)
        XCTAssertFalse(use(tracker), "a blip that recovers onto the same path costs nothing")
        XCTAssertEqual(tracker.pathInUse, home)
    }

    func testAChangeBackToThePathInUseCancelsAChangeAlreadyMarked() {
        let tracker = tracker()
        let home = identity()
        tracker.observe(home)

        clock.advance(10)
        tracker.observe(identity(interfaceName: "pdp_ip0", interfaceType: "cellular"))
        tracker.observe(home)

        clock.advance(10)
        XCTAssertFalse(
            use(tracker),
            "no request took the marking, so connectivity is still the one built for home and "
                + "there is nothing to rebuild")
        XCTAssertEqual(tracker.pathInUse, home)
    }

    func testAChangeBackAfterARequestTookTheMarkingRebuildsAgain() {
        let tracker = tracker()
        let home = identity()
        tracker.observe(home)

        clock.advance(10)
        tracker.observe(identity(interfaceName: "pdp_ip0", interfaceType: "cellular"))
        XCTAssertTrue(use(tracker))

        clock.advance(10)
        tracker.observe(home)
        XCTAssertTrue(
            use(tracker), "connectivity is built for cellular now, so home is a change again")
    }

    func testAChangeInsideTheDebounceWindowIsCommittedLaterNotDropped() {
        let tracker = tracker()
        tracker.observe(identity())
        clock.advance(10)

        tracker.observe(identity(interfaceName: "pdp_ip0", interfaceType: "cellular"))
        XCTAssertTrue(use(tracker), "the leading edge marks at once; the rebuild is lazy anyway")

        clock.advance(0.05)
        tracker.observe(identity(interfaceName: "utun3", interfaceType: "other"))
        XCTAssertFalse(
            use(tracker),
            "still inside the window: marking again here would make a rebuild already running be "
                + "thrown away and redone")

        clock.advance(StalenessTracker.debounceWindow)
        XCTAssertTrue(use(tracker), "and the change is committed once the window has passed")
        XCTAssertEqual(tracker.pathInUse?.interfaceName, "utun3")
    }

    func testChangesFurtherApartThanTheWindowEachMarkStale() {
        let tracker = tracker()
        tracker.observe(identity())

        clock.advance(StalenessTracker.debounceWindow)
        tracker.observe(identity(interfaceName: "pdp_ip0", interfaceType: "cellular"))
        XCTAssertTrue(use(tracker))

        clock.advance(StalenessTracker.debounceWindow)
        tracker.observe(identity(interfaceName: "utun3", interfaceType: "other"))
        XCTAssertTrue(use(tracker))
    }

    func testAnIdleGapReChecksThePathAndRebuildsOnlyOnARealChange() {
        let tracker = tracker(idleThreshold: 50)
        let home = identity()
        tracker.observe(home)
        XCTAssertFalse(use(tracker) { home })

        clock.advance(60)
        XCTAssertFalse(use(tracker) { home }, "the same path after a long gap is the same path")

        clock.advance(60)
        XCTAssertTrue(
            use(tracker) { identity(interfaceName: "pdp_ip0", interfaceType: "cellular") },
            "no update is guaranteed while suspended; the gap is where a missed change is caught")
    }

    func testAnIdleGapWithNoPathToReadRebuildsDefensively() {
        let tracker = tracker(idleThreshold: 50)
        tracker.observe(identity())
        _ = use(tracker) { identity() }

        clock.advance(60)

        XCTAssertTrue(use(tracker) { nil }, "not being able to check is itself a reason to rebuild")
    }

    func testARequestInsideTheIdleThresholdDoesNotReCheck() {
        let tracker = tracker(idleThreshold: 50)
        tracker.observe(identity())
        _ = use(tracker) { identity() }

        clock.advance(49)

        var probed = false
        XCTAssertFalse(
            use(tracker) {
                probed = true
                return identity(interfaceName: "pdp_ip0")
            })
        XCTAssertFalse(probed, "a warm client must not pay for the check on every request")
    }

    func testALongRequestDoesNotMakeTheRequestAfterItLookIdle() {
        let tracker = tracker(idleThreshold: 50)
        tracker.observe(identity())
        _ = use(tracker) { identity() }

        // A minute-long request: it starts now and finishes a minute later.
        clock.advance(60)
        tracker.onUseComplete()

        clock.advance(10)
        var probed = false
        XCTAssertFalse(
            use(tracker) {
                probed = true
                return nil
            })
        XCTAssertFalse(probed, "the gap is measured from when the last request ended")
    }

    func testAManualResetMeansTheNextRequestDoesNotResetAgain() {
        let tracker = tracker()
        tracker.observe(identity())
        clock.advance(10)
        tracker.observe(identity(interfaceName: "pdp_ip0", interfaceType: "cellular"))

        tracker.onManualReset()

        XCTAssertFalse(use(tracker), "the application already asked for the rebuild")
    }

    func testTheIdleThresholdFollowsTheConfiguredIdleConnectionTimeout() {
        XCTAssertEqual(
            StalenessTracker.idleThreshold(forIdleConnectionTimeout: 10),
            StalenessTracker.minIdleThreshold,
            "under the floor, the floor wins: a short connection timeout is not a reason to "
                + "re-check between two ordinary requests")
        XCTAssertEqual(StalenessTracker.idleThreshold(forIdleConnectionTimeout: 60), 120)
    }

    func testNothingIsStaleBeforeAnyObservationAtAll() {
        XCTAssertNil(tracker().pathInUse)
    }

    func testMarkingIsLogged() {
        let tracker = tracker()
        tracker.observe(identity())
        clock.advance(10)
        tracker.observe(identity(interfaceName: "pdp_ip0", interfaceType: "cellular"))

        XCTAssertTrue(log.debugs.contains { $0.contains("rebuilt on the next request") })
    }
}

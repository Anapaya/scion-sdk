// Copyright 2026 Anapaya Systems
import Foundation

/// Decides when connectivity has to be rebuilt.
///
/// The first observation is adopted as the path in use and marks nothing.
///
/// An observation of a path that is not satisfied is ignored.
///
/// A different path marks connectivity stale, at most once per `debounceWindow`. A change arriving
/// inside the suppression window is remembered and committed at the next observation or the next
/// request, so nothing is dropped.
///
/// A change back to the path in use cancels the rebuild, whether it was remembered or already
/// marked. A brief loss that recovers onto the same path is exactly the case where the right answer
/// is to do nothing.
///
/// Finally, a request after a long idle gap re-checks the path itself. No update is guaranteed
/// while the application is suspended, so a returning application cannot trust that it was told.
/// Rather than rebuilding blindly, it asks what the current path is and compares.
final class StalenessTracker: Sendable {
    /// How long one marking suppresses the next.
    static let debounceWindow: TimeInterval = 0.5

    /// The floor for the idle gap, whatever the configured connection timeouts are.
    static let minIdleThreshold: TimeInterval = 30

    /// The idle gap for a client whose idle connections are swept after `idleConnectionTimeout`.
    static func idleThreshold(forIdleConnectionTimeout timeout: TimeInterval) -> TimeInterval {
        max(2 * timeout, minIdleThreshold)
    }

    private struct State {
        /// The path connectivity was built for.
        var pathInUse: NetworkIdentity?
        /// The newest usable path the platform reported.
        var lastObserved: NetworkIdentity?
        var remembered: NetworkIdentity?
        var stale = false
        var lastMarked: TimeInterval = -.infinity
        var lastUse: TimeInterval?
    }

    private let clock: any MonotonicClock
    private let idleThreshold: TimeInterval
    private let log: any LibraryLog
    private let debounceWindow: TimeInterval
    private let state = Locked(State())

    init(
        clock: any MonotonicClock, idleThreshold: TimeInterval, log: any LibraryLog,
        debounceWindow: TimeInterval = StalenessTracker.debounceWindow
    ) {
        self.clock = clock
        self.idleThreshold = idleThreshold
        self.log = log
        self.debounceWindow = debounceWindow
    }

    /// Records what the platform reported. Called on the monitor's queue.
    func observe(_ identity: NetworkIdentity) {
        state.withLock { s in
            guard identity.isUsable else { return }
            guard let pathInUse = s.pathInUse else {
                s.pathInUse = identity
                s.lastObserved = identity
                s.lastMarked = clock.now()
                return
            }
            if let lastObserved = s.lastObserved, identity.isSameNetwork(as: lastObserved) {
                return
            }
            s.lastObserved = identity
            if identity.isSameNetwork(as: pathInUse) {
                s.stale = false
                s.remembered = nil
                return
            }
            let now = clock.now()
            if now - s.lastMarked >= debounceWindow {
                mark(&s, identity, now)
            } else {
                s.remembered = identity
            }
        }
    }

    /// Called before a request is issued: returns whether connectivity has to be rebuilt first.
    func onUseAttempt(probe: () -> NetworkIdentity?) -> Bool {
        state.withLock { s in
            let now = clock.now()
            commitRememberedIfDue(&s, now)
            checkIdleGap(&s, now, probe)
            s.lastUse = now
            let stale = s.stale
            s.stale = false
            if stale, let lastObserved = s.lastObserved {
                s.pathInUse = lastObserved
            }
            return stale
        }
    }

    /// Called when a request finishes.
    func onUseComplete() {
        state.withLock { $0.lastUse = clock.now() }
    }

    /// Called when the application asks for a rebuild itself, so the next request does not repeat
    /// it.
    func onManualReset() {
        state.withLock { s in
            s.stale = false
            s.remembered = nil
            if let lastObserved = s.lastObserved {
                s.pathInUse = lastObserved
            }
            let now = clock.now()
            s.lastMarked = now
            s.lastUse = now
        }
    }

    /// The path the last rebuild was made for. Test and diagnostic use.
    var pathInUse: NetworkIdentity? {
        state.withLock { $0.pathInUse }
    }

    private func mark(_ s: inout State, _ identity: NetworkIdentity, _ now: TimeInterval) {
        s.lastObserved = identity
        s.remembered = nil
        s.stale = true
        s.lastMarked = now
        log.debug("the network path changed; connectivity will be rebuilt on the next request")
    }

    private func commitRememberedIfDue(_ s: inout State, _ now: TimeInterval) {
        guard let remembered = s.remembered else { return }
        if now - s.lastMarked >= debounceWindow {
            mark(&s, remembered, now)
        }
    }

    private func checkIdleGap(
        _ s: inout State, _ now: TimeInterval, _ probe: () -> NetworkIdentity?
    ) {
        guard let lastUse = s.lastUse, now - lastUse >= idleThreshold else { return }
        // Being unable to ask is itself a reason to rebuild.
        let current = probe()
        guard let pathInUse = s.pathInUse else {
            if let current {
                mark(&s, current, now)
            }
            return
        }
        if let current, current.isSameNetwork(as: pathInUse) {
            return
        }
        mark(&s, current ?? pathInUse, now)
    }
}

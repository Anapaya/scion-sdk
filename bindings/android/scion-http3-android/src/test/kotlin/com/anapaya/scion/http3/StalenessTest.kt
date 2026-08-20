// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3

import com.anapaya.scion.http3.internal.NetworkIdentity
import com.anapaya.scion.http3.internal.StalenessTracker
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The state machine that decides when connectivity is rebuilt.
 *
 * This is the part of the library with real decisions in it, and every one of them is a bug someone
 * would otherwise hit on a moving device: rebuilding when nothing changed, not rebuilding when
 * something did, or rebuilding twice for one change. A fake clock makes all of it instant and
 * deterministic, which a device test of the same rules could never be.
 *
 * What these tests cannot show is that Android reports what they assume it reports. If
 * `onCapabilitiesChanged` never arrives with the validated capability on some device, every test here
 * still passes; that assumption is the instrumented tier's to check.
 */
class StalenessTest {
    private val clock = FakeClock()
    private val log = RecordingLog()

    private fun tracker(idleThresholdMillis: Long = 50_000) =
        StalenessTracker(clock, idleThresholdMillis, log)

    private fun StalenessTracker.use(probe: () -> NetworkIdentity? = { null }) = onUseAttempt(probe)

    @Test
    fun `a fresh client is not stale`() {
        val tracker = tracker()
        assertFalse(tracker.use(), "nothing has changed yet, so there is nothing to rebuild")
    }

    @Test
    fun `the first observation is adopted without marking anything stale`() {
        val tracker = tracker()

        tracker.observe(identity())

        assertEquals(identity(), tracker.baseline())
        assertFalse(
            tracker.use(),
            "registering a callback reports the current network at once, and a client that has " +
                "not connected yet has nothing stale about it",
        )
    }

    @Test
    fun `a network that is not usable yet is ignored`() {
        val tracker = tracker()
        tracker.observe(identity(handle = 1))

        tracker.observe(identity(handle = 2, validated = false))
        tracker.observe(identity(handle = 2, addresses = emptySet()))

        assertFalse(tracker.use(), "a network is reported before it can carry anything")
        assertEquals(1, tracker.baseline()?.handle)
    }

    @Test
    fun `a validated change to another network marks stale once`() {
        val tracker = tracker()
        tracker.observe(identity(handle = 1))
        clock.advance(10_000)

        tracker.observe(
            identity(handle = 2, interfaceName = "rmnet0", addresses = setOf("10.1.2.3/30")),
        )

        assertTrue(tracker.use(), "the first request after a change rebuilds")
        assertFalse(tracker.use(), "the second does not, because the first already did")
    }

    @Test
    fun `capability churn on the same network changes nothing`() {
        val tracker = tracker()
        tracker.observe(identity())
        clock.advance(10_000)

        repeat(5) { tracker.observe(identity()) }

        assertFalse(
            tracker.use(),
            "metered status and signal strength change constantly and mean nothing here",
        )
    }

    @Test
    fun `an address change on the same network marks stale`() {
        val tracker = tracker()
        tracker.observe(identity(handle = 7, addresses = setOf("192.168.1.10/24")))
        clock.advance(10_000)

        tracker.observe(identity(handle = 7, addresses = setOf("192.168.4.20/24")))

        assertTrue(
            tracker.use(),
            "Android keeps the handle across a DHCP renewal, and the new address is what " +
                "invalidates the sockets underneath",
        )
    }

    @Test
    fun `a change back to the network in use cancels a remembered change`() {
        val tracker = tracker()
        val home = identity(handle = 1)
        tracker.observe(home)

        // Inside the debounce window, so this is remembered rather than acted on.
        clock.advance(100)
        tracker.observe(identity(handle = 2, interfaceName = "rmnet0"))
        tracker.observe(home)

        clock.advance(10_000)
        assertFalse(tracker.use(), "a blip that recovers onto the same network costs nothing")
        assertEquals(home, tracker.baseline())
    }

    @Test
    fun `a change inside the debounce window is committed later, not dropped`() {
        val tracker = tracker()
        tracker.observe(identity(handle = 1))
        clock.advance(10_000)

        tracker.observe(identity(handle = 2, interfaceName = "rmnet0"))
        assertTrue(
            tracker.use(),
            "the leading edge marks at once, since the rebuild is lazy anyway",
        )

        clock.advance(50)
        tracker.observe(identity(handle = 3, interfaceName = "rmnet1"))
        assertFalse(
            tracker.use(),
            "still inside the window: marking again here would make a rebuild already running be " +
                "thrown away and redone",
        )

        clock.advance(StalenessTracker.DEBOUNCE_WINDOW_MILLIS)
        assertTrue(tracker.use(), "and the change is committed once the window has passed")
        assertEquals(3, tracker.baseline()?.handle)
    }

    @Test
    fun `changes further apart than the window each mark stale`() {
        val tracker = tracker()
        tracker.observe(identity(handle = 1))

        clock.advance(StalenessTracker.DEBOUNCE_WINDOW_MILLIS)
        tracker.observe(identity(handle = 2, interfaceName = "rmnet0"))
        assertTrue(tracker.use())

        clock.advance(StalenessTracker.DEBOUNCE_WINDOW_MILLIS)
        tracker.observe(identity(handle = 3, interfaceName = "rmnet1"))
        assertTrue(tracker.use())
    }

    @Test
    fun `an idle gap re-checks the network and rebuilds only on a real change`() {
        val tracker = tracker(idleThresholdMillis = 50_000)
        val home = identity(handle = 1)
        tracker.observe(home)
        assertFalse(tracker.use { home })

        clock.advance(60_000)
        assertFalse(
            tracker.use { home },
            "the same network after a long gap is still the same network",
        )

        clock.advance(60_000)
        assertTrue(
            tracker.use { identity(handle = 2, interfaceName = "rmnet0") },
            "callbacks are dropped while dozing, so the gap is where a missed change is caught",
        )
    }

    @Test
    fun `an idle gap with no network to read rebuilds defensively`() {
        val tracker = tracker(idleThresholdMillis = 50_000)
        tracker.observe(identity())
        tracker.use { identity() }

        clock.advance(60_000)

        assertTrue(tracker.use { null }, "not being able to check is itself a reason to rebuild")
    }

    @Test
    fun `a request inside the idle threshold does not re-check`() {
        val tracker = tracker(idleThresholdMillis = 50_000)
        tracker.observe(identity())
        tracker.use { identity() }

        clock.advance(49_000)

        var probed = false
        assertFalse(
            tracker.use {
                probed = true
                identity(handle = 999)
            },
        )
        assertFalse(probed, "a warm client must not pay for the check on every request")
    }

    @Test
    fun `a long request does not make the request after it look idle`() {
        val tracker = tracker(idleThresholdMillis = 50_000)
        tracker.observe(identity())
        tracker.use { identity() }

        // A minute-long request: it starts now and finishes a minute later.
        clock.advance(60_000)
        tracker.onUseComplete()

        clock.advance(10_000)
        var probed = false
        assertFalse(
            tracker.use {
                probed = true
                null
            },
        )
        assertFalse(probed, "the gap is measured from when the last request ended")
    }

    @Test
    fun `a manual reset means the next request does not reset again`() {
        val tracker = tracker()
        tracker.observe(identity(handle = 1))
        clock.advance(10_000)
        tracker.observe(identity(handle = 2, interfaceName = "rmnet0"))

        tracker.onManualReset()

        assertFalse(tracker.use(), "the application already asked for the rebuild")
    }

    @Test
    fun `a probe that throws is absorbed`() {
        val tracker = tracker(idleThresholdMillis = 1_000)
        tracker.observe(identity())
        tracker.use { identity() }
        clock.advance(10_000)

        assertTrue(tracker.use { throw IllegalStateException("system service went away") })
        assertTrue(log.warnings.any { it.contains("could not read the current network") })
    }

    @Test
    fun `the idle threshold follows the configured idle connection timeout`() {
        assertEquals(
            StalenessTracker.MIN_IDLE_THRESHOLD_MILLIS,
            StalenessTracker.idleThresholdFor(10_000),
            "under the floor, the floor wins: a short connection timeout is not a reason to " +
                "re-check between two ordinary requests",
        )
        assertEquals(120_000, StalenessTracker.idleThresholdFor(60_000))
    }

    @Test
    fun `nothing is stale before any observation at all`() {
        val tracker = tracker()
        assertNull(tracker.baseline())
    }
}

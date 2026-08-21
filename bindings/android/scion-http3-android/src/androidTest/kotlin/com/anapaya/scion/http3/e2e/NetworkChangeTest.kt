// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.e2e

import android.net.ConnectivityManager
import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.anapaya.scion.http3.internal.AndroidLog
import com.anapaya.scion.http3.internal.ConnectivityNetworkMonitor
import com.anapaya.scion.http3.internal.NetworkIdentity
import com.anapaya.scion.http3.internal.NetworkMonitor
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * The device's network going away and coming back.
 *
 * An emulator has one usable network, so a Wi-Fi-to-cellular handover is not possible. We use
 * airplane mode to take the network down and back up again.
 */
@RunWith(AndroidJUnit4::class)
class NetworkChangeTest {
    @After
    fun restoreConnectivity() {
        setNetwork(up = true)
    }

    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun aClientRecoversAfterTheNetworkGoesAndComesBack() =
        runBlocking {
            // The monitor the client would build for itself, wrapped so this test can see what the
            // platform delivered to it. The pool timeout is far longer than this test, which keeps
            // the sweep from being the thing that recovers.
            val monitor =
                RecordingNetworkMonitor(ConnectivityNetworkMonitor(Fixture.context, AndroidLog))
            val client =
                Fixture
                    .clientBuilder()
                    .idleConnectionTimeout(POOL_TIMEOUT)
                    .networkMonitor(monitor)
                    .build()
            client.use { _ ->
                assertEquals(200, client.getFromFixture("/hello").use { it.code })
                val before = monitor.observed().lastOrNull { it.isUsable }

                // Both calls fail the test unless the platform really loses and regains its default
                // network. Nothing is asserted about a request while it is down: a request then
                // fails after a connect timeout, which says only that there is no network, and
                // waiting for it would spend the test budget saying what the check below already
                // said in milliseconds.
                setNetwork(up = false)
                setNetwork(up = true)

                val change = awaitChangeFrom(before, monitor)
                assertTrue("the network reported after the outage is not usable", change.isUsable)
                assertTrue(
                    "the platform reported the same network as before the outage, so the library " +
                        "had nothing to act on: $change",
                    before == null || !change.isSameNetworkAs(before),
                )

                // And the client works again, with no reset() and no new client. The deadline keeps
                // the recovery attributable to the change above: the pool sweep is set far beyond
                // it, and it is under the thirty-second QUIC idle timeout, so neither of those can
                // be what restored connectivity.
                assertEquals(200, client.getUntilItWorks("/hello", RECOVERY_DEADLINE))
            }
        }

    /** Waits for the monitor to report a usable network other than [before], and returns it. */
    private fun awaitChangeFrom(
        before: NetworkIdentity?,
        monitor: RecordingNetworkMonitor,
    ): NetworkIdentity {
        val deadline = System.nanoTime() + SETTLE_DEADLINE.inWholeNanoseconds
        while (System.nanoTime() < deadline) {
            val latest = monitor.observed().lastOrNull { it.isUsable }
            if (latest != null && (before == null || !latest.isSameNetworkAs(before))) return latest
            Thread.sleep(POLL.inWholeMilliseconds)
        }
        throw AssertionError(
            "the client's network callback reported nothing it could act on within " +
                "$SETTLE_DEADLINE of the outage ending, so nothing here would have rebuilt " +
                "connectivity",
        )
    }

    /**
     * The monitor the client uses, with a note of everything it delivered.
     *
     * Wrapping rather than standing in for it: the point is the platform's own callbacks, so the
     * thing being watched has to be what receives them.
     */
    private class RecordingNetworkMonitor(
        private val delegate: NetworkMonitor,
    ) : NetworkMonitor {
        // Appended from a framework callback thread and read from the test's.
        private val seen = CopyOnWriteArrayList<NetworkIdentity>()

        fun observed(): List<NetworkIdentity> = seen.toList()

        override fun start(onObserved: (NetworkIdentity) -> Unit) =
            delegate.start { identity ->
                seen += identity
                onObserved(identity)
            }

        override fun currentIdentity(): NetworkIdentity? = delegate.currentIdentity()

        override fun stop() = delegate.stop()
    }

    /**
     * Takes the device's network down or brings it back, and does not return until the platform
     * agrees that it happened.
     *
     * Waiting on the platform's own view rather than on what the command printed is the whole point.
     * `executeShellCommand` hands back standard output only, and a service that is missing from a
     * stripped image says so on standard error, so a reply that looks empty says nothing about
     * whether anything happened. A test that took an unnoticed failure for success would then
     * "recover" from an outage that never occurred, which is the one way this test can be worse than
     * absent.
     *
     * `cmd connectivity` needs a recent enough platform and an image that carries the service;
     * `svc` reaches the same radios by another route, and is tried when the first had no effect.
     */
    private fun setNetwork(up: Boolean) {
        shell("cmd connectivity airplane-mode ${if (up) "disable" else "enable"}")
        if (awaitNetwork(up)) return

        val svc = if (up) "enable" else "disable"
        shell("svc wifi $svc")
        shell("svc data $svc")
        check(awaitNetwork(up)) {
            val wanted = if (up) "back up" else "down"
            "the device's network did not come $wanted within $SETTLE_DEADLINE. Neither " +
                "`cmd connectivity airplane-mode` nor `svc` had any effect, so this emulator " +
                "image cannot run this test."
        }
    }

    /** Whether the platform reports a default network matching [up] before the deadline. */
    private fun awaitNetwork(up: Boolean): Boolean {
        val manager =
            Fixture.context.getSystemService(ConnectivityManager::class.java)
                ?: throw AssertionError("this device has no ConnectivityManager")
        val deadline = System.nanoTime() + SETTLE_DEADLINE.inWholeNanoseconds
        while (System.nanoTime() < deadline) {
            if ((manager.activeNetwork != null) == up) return true
            Thread.sleep(POLL.inWholeMilliseconds)
        }
        return false
    }

    private fun shell(command: String): String {
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        return ParcelFileDescriptor
            .AutoCloseInputStream(automation.executeShellCommand(command))
            .use { it.bufferedReader().readText() }
    }

    private companion object {
        /** How long the radios may take to go or come back before the image is declared unusable. */
        val SETTLE_DEADLINE: Duration = 30.seconds
        val POLL: Duration = 250.milliseconds

        /** Long enough that neither the pool sweep nor the idle-gap re-check can fire in this test. */
        val POOL_TIMEOUT: Duration = 5.minutes

        /**
         * Deliberately under the QUIC idle timeout of thirty seconds, so that expiry cannot be what
         * restores connectivity. Recovery itself takes a second or two once the radios are back, and
         * `setNetwork` has already waited for that, so the rest is headroom for a slow emulator.
         */
        val RECOVERY_DEADLINE: Duration = 20.seconds
    }
}

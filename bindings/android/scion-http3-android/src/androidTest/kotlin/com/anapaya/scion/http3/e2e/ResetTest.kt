// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.e2e

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.anapaya.scion.http3.ScionHttp3Exception
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * E2e test for [ScionHttp3Client.reset].
 */
@RunWith(AndroidJUnit4::class)
class ResetTest {
    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun aResetFaultsWhatWasInFlightAndTheNextRequestRebuilds() =
        runBlocking {
            // A request timeout beyond the slow response, so that running out of time cannot be
            // what ends the in-flight request. Whatever ends it can then only be the reset.
            Fixture.clientBuilder().requestTimeout(REQUEST_TIMEOUT).build().use { client ->
                // Warm the connection up, so what follows is a rebuild rather than a first build.
                assertEquals(200, client.getFromFixture("/hello").use { it.code })

                val slow =
                    async {
                        try {
                            client.getFromFixture("/slow?ms=$SLOW_MILLIS").close()
                            null
                        } catch (e: ScionHttp3Exception) {
                            e
                        }
                    }

                awaitStarted(SLOW_PATH)

                client.reset()

                assertEquals(200, client.getFromFixture("/hello").use { it.code })

                val failure = slow.await()
                assertNotNull("the request that was in flight was not faulted", failure)
                assertEquals(
                    "the server completed the request the reset was supposed to cut off",
                    0L,
                    Fixture.requestsCompleted(SLOW_PATH),
                )
            }
        }

    /** Waits until the server has seen a request for [path] arrive. */
    private suspend fun awaitStarted(path: String) {
        val deadline = System.nanoTime() + START_DEADLINE.inWholeNanoseconds
        while (System.nanoTime() < deadline) {
            if (Fixture.requestsStarted(path) > 0) return
            delay(POLL)
        }
        throw AssertionError("the server never saw a request for $path within $START_DEADLINE")
    }

    private companion object {
        /** Long enough that a request which merely completed cannot be mistaken for a faulted one. */
        const val SLOW_MILLIS = 120_000
        const val SLOW_PATH = "/slow"
        val REQUEST_TIMEOUT: Duration = 5.minutes
        val START_DEADLINE: Duration = 60.seconds
        val POLL: Duration = 250.milliseconds
    }
}

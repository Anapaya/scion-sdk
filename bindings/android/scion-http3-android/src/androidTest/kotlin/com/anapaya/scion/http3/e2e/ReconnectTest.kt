// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.e2e

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * A client that keeps working after the server it is talking to goes away and comes back.
 */
@RunWith(AndroidJUnit4::class)
class ReconnectTest {
    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun aRequestAfterARestartReachesTheServerAgain() =
        runBlocking {
            // A short pool timeout, so the dead connection is discarded in seconds rather than when
            // the QUIC idle timeout expires. How long a client takes to give up on a connection
            // nobody is answering is a matter of configuration, and this test is about what happens
            // afterwards.
            Fixture
                .clientBuilder()
                .idleConnectionTimeoutMillis(2_000)
                .build()
                .use { client ->
                    assertEquals(200, client.getFromFixture("/hello").use { it.code })

                    val restartsBefore = Fixture.restarts()
                    Fixture.restartServer()
                    // Without this the test passes when the restart quietly does nothing: the
                    // connection would still be good and the request below would simply work.
                    assertEquals(restartsBefore + 1, Fixture.restarts())

                    assertEquals(200, client.getUntilItWorks("/hello", RECONNECT_DEADLINE))
                }
        }

    private companion object {
        val RECONNECT_DEADLINE: Duration = 120.seconds
    }
}

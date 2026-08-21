// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.ffi

import com.anapaya.scion.http3.uniffi.ScionHttp3Client
import com.anapaya.scion.http3.uniffi.ScionHttp3Exception
import com.anapaya.scion.http3.uniffi.TrustAnchors
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.junit.jupiter.api.assertThrows
import java.util.concurrent.TimeUnit
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * The parts of the test server that only the instrumented tier uses.
 *
 * Those tests need an emulator and do not run on every change, so what they depend on is exercised
 * here instead: the description served over the control API, the restart that makes a client
 * reconnect, and the route that resets a stream partway through a response. A change that breaks
 * one of them then fails on the pull request rather than in the nightly emulator run.
 */
@Timeout(value = 5, unit = TimeUnit.MINUTES)
class FixtureTest {
    private val server = TestServer.shared

    @Test
    fun `the control api reports what the process printed`() {
        assertEquals(server.endpoints, server.info())
    }

    @Test
    fun `a client reconnects after the server restarts`(): Unit =
        runBlocking {
            // A server of its own: a restart drops every connection, and the shared one is in use
            // by whatever else this suite is running.
            TestServer.start().use { restarted ->
                // A short pool timeout, so the connection the restart killed is discarded in
                // seconds rather than when the QUIC idle timeout expires. Nothing tells a client
                // that a server went away, so how long it takes to find out is a matter of
                // configuration, and this test should not spend half a minute on it.
                clientFor(restarted) { it.copy(idleConnectionTimeoutMs = 2_000uL) }.use { client ->
                    assertEquals(200, client.execute(requestTo(restarted, "/hello")).status.toInt())

                    restarted.restartServer()

                    // Retried the way an application would. The first request after a restart goes
                    // out on a connection nothing on the other side knows about any more, and only
                    // one issued after the pool has given up on it can succeed.
                    assertEquals(200, getUntilItWorks(client, restarted, "/hello"))
                }
            }
        }

    @Test
    fun `the second authority the server reports signs nothing it presents`(): Unit =
        runBlocking {
            // Both certificates are self-signed for the same name and only one of them signed what
            // the server presents, so trust is the only thing separating this from the requests
            // every other test here makes.
            val pinnedToTheWrongOne =
                clientFor(server) {
                    it.copy(trust = TrustAnchors.Pem(server.endpoints.wrongCaPem.toByteArray()))
                }
            pinnedToTheWrongOne.use { client ->
                // Connect rather than Tls, which is where a rejected certificate belongs: the
                // handshake loop in scion-quic discards the cause and reports the same failure an
                // unreachable peer produces, so nothing downstream can tell the two apart. The
                // mapping in scion-http3 says so where it decides; this is what a caller sees until
                // that changes, and asserting it here means the day it does change is noticed.
                assertThrows<ScionHttp3Exception.Connect> {
                    client.execute(requestTo(server, "/hello"))
                }
            }
        }

    @Test
    fun `a stream reset partway through a response is reported as one`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                assertThrows<ScionHttp3Exception.StreamReset> {
                    client.execute(requestTo(server, "/reset-stream"))
                }
            }
        }

    /** Requests [path] until it answers or [RECONNECT_DEADLINE] passes, and reports its status. */
    private suspend fun getUntilItWorks(
        client: ScionHttp3Client,
        server: TestServer,
        path: String,
    ): Int {
        val deadline = System.nanoTime() + RECONNECT_DEADLINE.inWholeNanoseconds
        var last: ScionHttp3Exception? = null
        while (System.nanoTime() < deadline) {
            try {
                return client.execute(requestTo(server, path)).status.toInt()
            } catch (e: ScionHttp3Exception) {
                last = e
                delay(RETRY_DELAY)
            }
        }
        throw AssertionError("nothing succeeded within $RECONNECT_DEADLINE", last)
    }

    private companion object {
        val RECONNECT_DEADLINE: Duration = 90.seconds
        val RETRY_DELAY: Duration = 1.seconds
    }
}

// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.ffi

import com.anapaya.scion.http3.uniffi.uniffiContinuationHandleMap
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.util.concurrent.TimeUnit
import kotlin.system.measureTimeMillis

/**
 * The regression test for coroutine cancellation.
 *
 * Cancelling a coroutine cancels the request on the wire. That works because the generated Kotlin
 * frees the Rust future in a `finally` block, which drops the request future, which resets the
 * stream. UniFFI documents no such guarantee, and its own guide says cancellation is unsupported,
 * so this is an implementation property that a version bump could take away without a word. That
 * is why `uniffi` is pinned exactly, and why these assertions are worth their runtime: a bump of
 * uniffi, of kotlinx-coroutines, or of the runtime strategy in the Rust crate has to pass them.
 */
@Timeout(value = 3, unit = TimeUnit.MINUTES)
class CancellationTest {
    private val server = TestServer.shared

    @Test
    fun `cancelling releases the stream and leaves the connection usable`(): Unit =
        runBlocking {
            val tag = "cancel-regression"
            clientFor(server).use { client ->
                // Warm up, so this measures request teardown rather than handshake teardown.
                assertEquals(200, client.execute(requestTo(server, "/hello")).status.toInt())

                val request = requestTo(server, "/endless-body?tag=$tag")
                val call = launch(Dispatchers.Default) { client.execute(request) }
                awaitChunks(tag, atLeast = 3)

                // A coarse liveness bound, not a measurement of where the teardown runs: it catches
                // a teardown that deadlocks or waits on the network, and nothing finer.
                val blockedMs = measureTimeMillis { call.cancelAndJoin() }
                assertTrue(blockedMs < 1_000, "cancelAndJoin held the caller for $blockedMs ms")

                // The client says it cancelled. Check that the server heard about it.
                assertServerStoppedProducing(tag)

                // Ensure no continuation was left behind. The generated bindings keep a map of
                // in-flight futures, and cancelling a call has to remove the entry from that map.
                assertEquals(0, uniffiContinuationHandleMap.size, "a continuation was left behind")

                // One stream was cancelled, not the connection.
                val seenBefore = server.requestsSeen("/hello")
                assertEquals(200, client.execute(requestTo(server, "/hello")).status.toInt())
                assertEquals(seenBefore + 1, server.requestsSeen("/hello"))
            }
        }

    @Test
    fun `cancellation surfaces as a cancellation, not as a request failure`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                val call =
                    async(Dispatchers.Default) {
                        client.execute(requestTo(server, "/endless-body?tag=surface"))
                    }
                awaitChunks("surface", atLeast = 1)
                call.cancel()

                val thrown = runCatching { call.await() }.exceptionOrNull()
                assertTrue(
                    thrown is CancellationException,
                    "a cancelled call threw ${thrown?.javaClass?.name}",
                )
            }
        }

    @Test
    fun `a timeout around a call cancels it the same way`(): Unit =
        runBlocking {
            val tag = "with-timeout"
            clientFor(server).use { client ->
                // Warm the connection up first. Without it a client that spends the whole timeout
                // connecting produces no chunks at all, and everything below passes at zero.
                assertEquals(200, client.execute(requestTo(server, "/hello")).status.toInt())

                val outcome =
                    withTimeoutOrNull(2_000) {
                        client.execute(requestTo(server, "/endless-body?tag=$tag"))
                    }
                assertEquals(null, outcome, "the endless body ended on its own")
                assertTrue(server.endlessChunks(tag) > 0, "the server never started sending")
                assertServerStoppedProducing(tag)
            }
        }

    /**
     * The negative control. Without it, the tests above could be passing because something else
     * ends the request, and nobody would know.
     */
    @Test
    fun `a call that cannot be cancelled runs to completion`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                var status: UShort? = null
                val call =
                    launch(Dispatchers.Default) {
                        withContext(NonCancellable) {
                            status = client.execute(requestTo(server, "/slow?ms=1500")).status
                        }
                    }
                delay(300)
                call.cancelAndJoin()

                assertNotNull(status, "the uncancellable call was cancelled after all")
            }
        }

    /**
     * Cancelling before the call is dispatched must leave nothing behind either: the body never
     * ran, so there is no Rust future, and the bookkeeping has to agree.
     */
    @Test
    fun `cancelling before dispatch leaks nothing`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                repeat(50) {
                    val call =
                        launch(Dispatchers.Default) {
                            client.execute(requestTo(server, "/hello"))
                        }
                    call.cancelAndJoin()
                }
                assertEquals(0, uniffiContinuationHandleMap.size)
            }
        }

    /**
     * Checks that the server has stopped sending the endless body for [tag].
     *
     * The server keeps producing chunks until the client's `STOP_SENDING` reaches it. So a chunk
     * count that stops going up is how a test can see that the cancellation got to the server. The
     * client side cannot show this: `scion-http3` exposes no view of the stream.
     *
     * The count does not stop the moment the call is cancelled, because chunks already sent still
     * arrive. This therefore waits for it to stop first, and only then checks that it stays
     * stopped. Waiting rather than sleeping for a fixed time keeps it from failing on a slow
     * machine.
     *
     * Nothing else can stop the count. The server would also stop if it ran out of flow-control
     * credit, but that would take hours: the window is a megabyte and this body sends 80 bytes a
     * second.
     */
    private suspend fun assertServerStoppedProducing(tag: String) {
        var count = server.endlessChunks(tag)
        val stopped =
            withTimeoutOrNull(STOP_TIMEOUT_MS) {
                // Two consecutive polls have to agree. One is not enough: a poll can land inside the
                // 50 ms gap between chunks and read the same count as its predecessor while the
                // server is still sending.
                var quiet = 0
                while (quiet < QUIET_POLLS) {
                    delay(POLL_INTERVAL_MS)
                    val next = server.endlessChunks(tag)
                    quiet = if (next == count) quiet + 1 else 0
                    count = next
                }
                true
            }
        assertTrue(
            stopped == true,
            "the server was still sending $STOP_TIMEOUT_MS ms after the call was cancelled",
        )

        // Stopped, rather than merely slow: this window is worth about twenty chunks.
        delay(CONFIRM_WINDOW_MS)
        assertEquals(count, server.endlessChunks(tag), "the server started sending again")
    }

    /** Waits until the server has sent [atLeast] chunks for [tag]. */
    private suspend fun awaitChunks(
        tag: String,
        atLeast: Long,
    ) {
        val reached =
            withTimeoutOrNull(START_TIMEOUT_MS) {
                while (server.endlessChunks(tag) < atLeast) {
                    delay(POLL_INTERVAL_MS)
                }
                true
            }
        assertTrue(reached == true, "the server never started sending for $tag")
    }

    private companion object {
        /** How often the server's chunk count is read while waiting for it to change or settle. */
        const val POLL_INTERVAL_MS = 100L

        /** How long the server may take to start sending, which includes building connectivity. */
        const val START_TIMEOUT_MS = 30_000L

        /** How long the server may keep sending after a call was cancelled. */
        const val STOP_TIMEOUT_MS = 10_000L

        /** How long it then has to stay stopped. The endless body sends a chunk every 50 ms. */
        const val CONFIRM_WINDOW_MS = 1_000L

        /** Consecutive unchanged polls that count as stopped. */
        const val QUIET_POLLS = 2
    }
}

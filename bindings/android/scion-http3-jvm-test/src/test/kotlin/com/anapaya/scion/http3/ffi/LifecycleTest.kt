// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.ffi

import com.anapaya.scion.http3.uniffi.ScionHttp3Exception
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.junit.jupiter.api.assertThrows
import java.util.concurrent.TimeUnit
import kotlin.system.measureTimeMillis

/**
 * What closing a client does, and what it leaves usable.
 *
 * All of it is about the client, because there is nothing else to test: one runtime serves the
 * process and is never shut down, so there is no teardown to observe, to wait for, or to race with.
 */
@Timeout(value = 3, unit = TimeUnit.MINUTES)
class LifecycleTest {
    private val server = TestServer.shared

    @Test
    fun `a client can be created, shut down, and created again`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                assertEquals(200, client.execute(requestTo(server, "/hello")).status.toInt())

                client.shutdown()

                assertThrows<ScionHttp3Exception.Closed> {
                    client.execute(requestTo(server, "/hello"))
                }
            }

            // A closed client does not spoil the next one, which is the property that matters to an
            // application that closes on backgrounding and opens again on resume.
            clientFor(server).use { client ->
                assertEquals(200, client.execute(requestTo(server, "/hello")).status.toInt())
            }
        }

    @Test
    fun `two clients work at the same time`(): Unit =
        runBlocking {
            clientFor(server).use { first ->
                clientFor(server).use { second ->
                    assertEquals(200, first.execute(requestTo(server, "/hello")).status.toInt())
                    assertEquals(200, second.execute(requestTo(server, "/hello")).status.toInt())

                    // And closing one leaves the other alone: they share a runtime, so a shutdown
                    // that reached further than its own pool would show up here.
                    first.shutdown()
                    assertEquals(200, second.execute(requestTo(server, "/hello")).status.toInt())
                }
            }
        }

    @Test
    fun `shutdown faults an in-flight request instead of leaving it to time out`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                // Warm the connection up first, so shutdown has a pool to close.
                client.execute(requestTo(server, "/hello"))

                val inFlight =
                    async(Dispatchers.Default) {
                        runCatching { client.execute(requestTo(server, "/slow?ms=20000")) }
                    }
                delay(500)

                val elapsed =
                    measureTimeMillis {
                        client.shutdown()
                        inFlight.await()
                    }
                assertTrue(inFlight.await().isFailure, "the request outlived the client")
                // Its own timeout is 30 seconds, so anything near that means it was not faulted but
                // merely abandoned.
                assertTrue(elapsed < 10_000, "faulting the in-flight request took $elapsed ms")
            }
        }

    @Test
    fun `shutting down twice is not an error`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                client.execute(requestTo(server, "/hello"))
                client.shutdown()
                client.shutdown()
            }
        }

    /**
     * Destroying a client without shutting it down still closes its pool, on the runtime rather than
     * on the caller's thread. Nothing here can see the `CONNECTION_CLOSE` that produces, so this
     * asserts the part that is observable: it neither throws nor hangs, and the next client works.
     */
    @Test
    fun `a client destroyed without a shutdown does not disturb the next one`(): Unit =
        runBlocking {
            val abandoned = clientFor(server)
            abandoned.execute(requestTo(server, "/hello"))
            abandoned.close()

            clientFor(server).use { client ->
                assertEquals(200, client.execute(requestTo(server, "/hello")).status.toInt())
            }
        }
}

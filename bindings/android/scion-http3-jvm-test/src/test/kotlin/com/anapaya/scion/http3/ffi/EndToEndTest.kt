// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.ffi

import com.anapaya.scion.http3.uniffi.ScionHttp3Exception
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.junit.jupiter.api.assertThrows
import java.util.concurrent.TimeUnit

/**
 * A request through the whole stack: generated Kotlin, the shared library, `scion-http3`, the SCION
 * data plane, and an HTTP/3 server in another AS of a PocketSCION topology.
 *
 * Everything else in this suite assumes this works, so if it fails, start here.
 */
@Timeout(value = 2, unit = TimeUnit.MINUTES)
class EndToEndTest {
    private val server = TestServer.shared

    @Test
    fun `a get returns the servers response`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                val response = client.execute(requestTo(server, "/hello"))

                assertEquals(200, response.status.toInt())
                assertEquals("world", response.body.asText())
            }
        }

    @Test
    fun `a post sends its body and gets it back byte for byte`(): Unit =
        runBlocking {
            // Bytes that are not text, including a lone continuation byte, so that anything
            // treating the body as a string on the way through is caught.
            val payload = byteArrayOf(0x00, 0x7f, -0x01, -0x80, 0x61)

            clientFor(server).use { client ->
                val response =
                    client.execute(
                        requestTo(server, "/echo") { it.copy(method = "POST", body = payload) },
                    )

                assertEquals(200, response.status.toInt())
                assertArrayEquals(payload, response.body)
            }
        }

    @Test
    fun `a second request reuses the first requests connection`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                val seenBefore = server.requestsSeen("/hello")

                assertEquals(200, client.execute(requestTo(server, "/hello")).status.toInt())
                assertEquals(200, client.execute(requestTo(server, "/hello")).status.toInt())

                assertEquals(seenBefore + 2, server.requestsSeen("/hello"))
            }
        }

    /**
     * `warmUp` reaches Rust and reports.
     *
     * Only the failure half is available here. It takes a URL and nothing else, so establishing a
     * connection with it means resolving the host through DNS, and this topology has no TSAR records
     * to resolve against; a success-path test would need a resolver this tier deliberately does not
     * depend on. A malformed URL fails before any of that, which at least keeps the export from
     * having no caller at all.
     */
    @Test
    fun `warm up rejects a url it cannot use`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                assertThrows<ScionHttp3Exception.InvalidRequest> { client.warmUp("not a url") }
                // http, not https: an HTTP/3 client has nothing to fall back to.
                assertThrows<ScionHttp3Exception.InvalidRequest> {
                    client.warmUp("http://example.org/")
                }
            }
        }
}

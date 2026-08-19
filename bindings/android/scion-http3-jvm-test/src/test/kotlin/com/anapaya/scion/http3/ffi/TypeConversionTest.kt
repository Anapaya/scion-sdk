// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.ffi

import com.anapaya.scion.http3.uniffi.Header
import com.google.gson.JsonParser
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.util.concurrent.TimeUnit

/**
 * What each type looks like once it has been through the boundary twice.
 */
@Timeout(value = 2, unit = TimeUnit.MINUTES)
class TypeConversionTest {
    private val server = TestServer.shared

    @Test
    fun `methods reach the server as sent`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                // Including one nothing along the path can have a special case for.
                for (method in listOf("GET", "POST", "DELETE", "PATCH", "REPORT")) {
                    val response =
                        client.execute(requestTo(server, "/method") { it.copy(method = method) })
                    assertEquals(method, response.body.asText())
                }
            }
        }

    @Test
    fun `repeated request headers arrive in order and are not merged`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                val response =
                    client.execute(
                        requestTo(server, "/echo-headers") {
                            it.copy(
                                headers =
                                    listOf(
                                        Header("x-trace", "first"),
                                        Header("x-trace", "second"),
                                        Header("accept", "application/json"),
                                    ),
                            )
                        },
                    )

                val received =
                    JsonParser
                        .parseString(response.body.asText())
                        .asJsonArray
                        .map { it.asJsonObject }
                        .filter { it.get("name").asString == "x-trace" }
                        .map { it.get("value").asString }
                assertEquals(listOf("first", "second"), received)
            }
        }

    @Test
    fun `repeated response headers arrive in order and are not merged`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                val response = client.execute(requestTo(server, "/repeated-headers"))

                val cookies = response.headers.filter { it.name == "set-cookie" }.map { it.value }
                // The route sets two deliberately, so anything that flattens a header map into a
                // map keyed by name loses one of them.
                assertEquals(listOf("a=1", "b=2"), cookies)
            }
        }

    @Test
    fun `status codes round trip, including ones nobody special cases`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                for (code in listOf(200, 204, 404, 418, 503)) {
                    val response = client.execute(requestTo(server, "/status/$code"))
                    assertEquals(code, response.status.toInt())
                }
            }
        }

    @Test
    fun `a trailing header section arrives separately from the headers`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                val response = client.execute(requestTo(server, "/trailers"))

                assertEquals("with trailers", response.body.asText())
                assertEquals(listOf(Header("x-checksum", "42")), response.trailers)
                assertTrue(
                    response.headers.none { it.name == "x-checksum" },
                    "a trailer was reported as a header",
                )
            }
        }

    @Test
    fun `an absent body and an empty body are both accepted`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                val absent = client.execute(requestTo(server, "/echo") { it.copy(method = "POST") })
                assertEquals(0, absent.body.size)

                val empty =
                    client.execute(
                        requestTo(
                            server,
                            "/echo",
                        ) { it.copy(method = "POST", body = ByteArray(0)) },
                    )
                assertEquals(0, empty.body.size)
            }
        }

    @Test
    fun `a body larger than one buffer survives both crossings`(): Unit =
        runBlocking {
            // Large enough to be split into many QUIC frames, so this covers reassembly rather than
            // just the copy across the boundary.
            val payload = ByteArray(1 shl 20) { (it % 251).toByte() }

            clientFor(server).use { client ->
                val response =
                    client.execute(
                        requestTo(server, "/echo") {
                            it.copy(
                                method = "POST",
                                body = payload,
                                maxResponseBodyBytes = (payload.size + 1).toULong(),
                            )
                        },
                    )

                assertArrayEquals(payload, response.body)
            }
        }

    @Test
    fun `a body that is not text is not decoded on the way through`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                val response = client.execute(requestTo(server, "/invalid-utf8"))
                // Bytes, not a string: nothing along the path may try to make text of this.
                assertArrayEquals(byteArrayOf(-0x01, -0x02), response.body)
            }
        }
}

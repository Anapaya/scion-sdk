// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.ffi

import com.anapaya.scion.http3.uniffi.ScionHttp3Exception
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.junit.jupiter.api.assertThrows
import java.util.concurrent.TimeUnit

/**
 * The token a client authenticates with, and replacing it while the client runs.
 *
 * The stack reads the token from a channel the client owns rather than calling back into Kotlin for
 * it, so there is no foreign callback on the request path: `setAuthToken` writes and the endhost-API
 * client reads.
 *
 * What a *wrong* token does is not covered here: the topology's endhost API does not reject one, so
 * a test asserting it would pass for the wrong reason. That the replaced value is the one handed out
 * is asserted in the Rust crate's `token` module, where the channel can be read directly.
 */
@Timeout(value = 3, unit = TimeUnit.MINUTES)
class AuthTokenTest {
    private val server = TestServer.shared

    @Test
    fun `the configured token authenticates a real request`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                val response = client.execute(requestTo(server, "/hello"))

                assertEquals(200.toUShort(), response.status)
            }
        }

    @Test
    fun `a token replaced after connectivity exists survives a rebuild`(): Unit =
        runBlocking {
            clientFor(server).use { client ->
                // The first request builds the connectivity that the replacement has to reach. A
                // replacement before this point would only ever be read by a stack built later,
                // which is the easy case.
                assertEquals(
                    200.toUShort(),
                    client.execute(requestTo(server, "/hello")).status,
                    "the client could not reach the topology before the token was replaced",
                )

                // A different value on purpose: re-setting the token it already holds is deduped
                // into a no-op and would prove nothing. The topology's endhost API accepts any
                // token, so the replacement stays usable.
                client.setAuthToken(server.endpoints.authToken + "-renewed")
                // Discards the built connectivity, so the next request re-runs discovery and reads
                // the token again instead of reusing a connection opened with the old one.
                client.reset()

                assertEquals(
                    200.toUShort(),
                    client.execute(requestTo(server, "/hello")).status,
                    "the client stopped working after its token was replaced and reset",
                )
            }
        }

    @Test
    fun `a client built without a token reports rather than silently ignoring one`(): Unit =
        runBlocking {
            clientFor(server) { it.copy(authToken = null) }.use { client ->
                // Nothing reads a token on this client, so accepting one would be a lie.
                assertThrows<ScionHttp3Exception.InvalidRequest> {
                    client.setAuthToken(server.endpoints.authToken)
                }
            }
        }
}

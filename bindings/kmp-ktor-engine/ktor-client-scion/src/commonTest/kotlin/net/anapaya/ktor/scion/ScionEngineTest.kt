// Copyright 2026 Anapaya Systems

package net.anapaya.ktor.scion

import io.ktor.client.call.body
import io.ktor.client.plugins.HttpRequestTimeoutException
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import uniffi.ktor_scion_core.CoreException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

class ScionEngineTest {

    private val base get() = TestNetwork.current.baseUrl

    @Test
    fun getReturnsStatusAndBody(): Unit = runEngineTest {
        scionClient().use { client ->
            val response = client.get("$base/hello")
            assertEquals(HttpStatusCode.OK, response.status)
            assertEquals("HTTP/3.0", response.version.toString())
            assertEquals("world", response.bodyAsText())
        }
    }

    @Test
    fun postSendsTheBodyBack(): Unit = runEngineTest {
        scionClient().use { client ->
            val response = client.post("$base/echo") {
                contentType(ContentType.Text.Plain)
                setBody("payload from kotlin")
            }
            assertEquals("payload from kotlin", response.bodyAsText())
        }
    }

    @Test
    fun requestHeadersReachTheServer(): Unit = runEngineTest {
        scionClient().use { client ->
            val response = client.get("$base/echo-headers") { header("X-Test", "from-kotlin") }
            val fields = response.bodyAsText()
            assertTrue(""""name":"x-test","value":"from-kotlin"""" in fields, fields)
        }
    }

    @Test
    fun repeatedResponseHeadersStaySeparate(): Unit = runEngineTest {
        scionClient().use { client ->
            val response = client.get("$base/repeated-headers")
            assertEquals(listOf("a=1", "b=2"), response.headers.getAll("Set-Cookie"))
        }
    }

    @Test
    fun errorStatusIsReportedNotThrown(): Unit = runEngineTest {
        scionClient().use { client ->
            assertEquals(HttpStatusCode.NotFound, client.get("$base/status/404").status)
        }
    }

    @Test
    fun largeBodyArrivesIntact(): Unit = runEngineTest {
        scionClient().use { client ->
            val size = 1 shl 20
            val body: ByteArray = client.get("$base/big?bytes=$size").body()
            assertEquals(size, body.size)
            assertTrue(body.all { it == 'x'.code.toByte() })
        }
    }

    @Test
    fun bodyAboveTheLimitFails(): Unit = runEngineTest {
        scionClient(engine = { maxResponseBodyBytes = 100 }).use { client ->
            val failure = assertFailsWith<ScionEngineException> { client.get("$base/big?bytes=1000") }
            assertIs<CoreException.BodyTooLarge>(failure.cause)
        }
    }

    @Test
    fun manyRequestsRunAtOnce(): Unit = runEngineTest {
        scionClient().use { client ->
            val bodies = coroutineScope {
                (1..50).map { async { client.get("$base/hello").bodyAsText() } }.awaitAll()
            }
            assertTrue(bodies.all { it == "world" })
        }
    }

    @Test
    fun requestTimeoutFailsTheCall(): Unit = runEngineTest {
        scionClient(client = { install(HttpTimeout) { requestTimeoutMillis = 300 } }).use { client ->
            assertFailsWith<HttpRequestTimeoutException> { client.get("$base/slow?ms=3000") }
        }
    }

    @Test
    fun cancellingTheCallerStopsTheRequest(): Unit = runEngineTest {
        scionClient().use { client ->
            // Builds the connection first, so the cancel below hits a request.
            client.get("$base/hello")

            // Start a slow request.
            val started = CompletableDeferred<Unit>()
            val job = launch {
                started.complete(Unit)
                client.get("$base/slow?ms=3000")
            }

            // Cancel it while it runs.
            started.await()
            delay(200)
            job.cancel()

            // A leaked request would keep this waiting for the full 3 s.
            val finished = withTimeoutOrNull(1_000) { job.join(); true }
            assertTrue(finished == true, "the cancelled request did not end")
            assertTrue(job.isCancelled)
        }
    }

    @Test
    fun untrustedCertificateBecomesAnEngineError(): Unit = runEngineTest {
        scionClient(engine = { caCertificatesPem = TestNetwork.current.wrongCaPem }).use { client ->
            val failure = assertFailsWith<ScionEngineException> { client.get("$base/hello") }
            // scion-http3 reports a rejected certificate as Connect, not Tls:
            // the handshake fails inside the connection attempts.
            assertIs<CoreException.Connect>(failure.cause)
        }
    }

    @Test
    fun closingTheClientEndsARequestInFlight(): Unit = runEngineTest {
        // Start a slow request.
        val client = scionClient()
        val job = launch { runCatching { client.get("$base/slow?ms=500") } }

        // Close the client while it runs.
        delay(100)
        client.close()

        // Check that the request ends.
        val finished = withTimeoutOrNull(5_000) { job.join(); true }
        assertTrue(finished == true, "close() left a request hanging")
    }

    @Test
    fun clientsCanBeOpenedAndClosedRepeatedly(): Unit = runEngineTest {
        repeat(5) {
            scionClient().use { client ->
                assertEquals("world", client.get("$base/hello").bodyAsText())
            }
        }
    }
}

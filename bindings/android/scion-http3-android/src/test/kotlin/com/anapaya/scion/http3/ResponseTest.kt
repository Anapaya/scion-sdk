// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3

import com.anapaya.scion.http3.internal.toPublic
import com.anapaya.scion.http3.uniffi.Header
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/**
 * What a response says, and the contract its body keeps.
 *
 * The `Closeable` behaviour is here because it is a promise about a version that does not exist yet:
 * bodies need no releasing today, and will need it when they stream. A test is what keeps the
 * behaviour from being quietly simplified away in the meantime, at which point every `use { }` in
 * every application would have to be written again.
 */
class ResponseTest {
    private fun responseOf(
        status: Int = 200,
        headers: List<Header> = emptyList(),
        body: ByteArray = ByteArray(0),
        trailers: List<Header> = emptyList(),
    ): ScionHttp3Response = response(status, headers, body, trailers).toPublic(request())

    @Test
    fun `a status is a response, not a failure`() {
        assertTrue(responseOf(status = 204).isSuccessful)
        assertFalse(responseOf(status = 404).isSuccessful)
        assertEquals(503, responseOf(status = 503).code)
        assertFalse(
            responseOf(status = 500).isSuccessful,
            "a server error is an answer the application decides about, not an exception",
        )
    }

    @Test
    fun `an absent trailer section is not an empty one`() {
        assertNull(responseOf().trailers, "no trailers were sent")
        assertEquals(
            "1",
            responseOf(trailers = listOf(Header("x-count", "1"))).trailers?.get("x-count"),
        )
    }

    @Test
    fun `a body reads as bytes and as text`(): Unit =
        runBlocking {
            val response = responseOf(body = "hello".toByteArray())

            assertArrayEquals("hello".toByteArray(), response.body.bytes())
            assertEquals("hello", response.body.string())
            assertEquals(5, response.body.contentLength)
        }

    @Test
    fun `a body that is not UTF-8 fails as text and reads as bytes`(): Unit =
        runBlocking {
            val bytes = byteArrayOf(0xFF.toByte(), 0xFE.toByte(), 0x00)
            val response = responseOf(body = bytes)

            val failure =
                assertThrows<ScionHttp3Exception.InvalidBody> {
                    runBlocking { response.body.string() }
                }
            assertFalse(failure.isRetryable, "the same bytes will arrive again")
            assertArrayEquals(
                bytes,
                response.body.bytes(),
                "a body that is not text is still a body, and reading it must stay possible",
            )
        }

    @Test
    fun `a body over the requested size is refused`(): Unit =
        runBlocking {
            val response = responseOf(body = ByteArray(2_048))

            val failure =
                assertThrows<ScionHttp3Exception.BodyTooLarge> {
                    runBlocking { response.body.bytes(maxSize = 1_024) }
                }
            assertEquals(1_024, failure.limit)
        }

    @Test
    fun `the bytes are copied, so one reader cannot change another's`(): Unit =
        runBlocking {
            val response = responseOf(body = "hello".toByteArray())

            response.body.bytes()[0] = 'X'.code.toByte()

            assertEquals("hello", response.body.string())
        }

    @Test
    fun `a closed body cannot be read, and closing twice is fine`(): Unit =
        runBlocking {
            val response = responseOf(body = "hello".toByteArray())

            response.body.close()
            response.body.close()

            assertThrows<IllegalStateException> { runBlocking { response.body.bytes() } }
            assertThrows<IllegalStateException> { runBlocking { response.body.string() } }
        }

    @Test
    fun `closing a response closes its body`(): Unit =
        runBlocking {
            val response = responseOf(body = "hello".toByteArray())

            response.use { assertEquals("hello", it.body.string()) }

            assertThrows<IllegalStateException> { runBlocking { response.body.bytes() } }
        }

    @Test
    fun `response headers keep their order and their repetitions`() {
        val response =
            responseOf(
                headers =
                    listOf(
                        Header("Content-Type", "application/json"),
                        Header("Set-Cookie", "a=1"),
                        Header("Set-Cookie", "b=2"),
                    ),
            )

        assertEquals(listOf("a=1", "b=2"), response.headers.values("set-cookie"))
        assertEquals(
            "application/json",
            response.headers["content-type"],
            "a header is found whatever case the server sent it in",
        )
        assertEquals(3, response.headers.size)
    }

    @Test
    fun `a response knows the request it answers`() {
        val request = request(url = "https://example.org/rooms")
        assertEquals(request, response().toPublic(request).request)
    }
}

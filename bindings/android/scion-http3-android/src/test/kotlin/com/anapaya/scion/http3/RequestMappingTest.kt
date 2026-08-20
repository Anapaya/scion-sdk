// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3

import com.anapaya.scion.http3.internal.toFfi
import com.anapaya.scion.http3.uniffi.Header
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/**
 * The distinctions a request mapper is most likely to lose.
 *
 * Each of these is a difference the stack below acts on, and which a plausible mapping erases: a
 * missing body becoming an empty one, repeated headers being merged, a target quietly carrying a
 * port. The FFI tier proves the stack honours them; this proves the library hands them over.
 */
class RequestMappingTest {
    @Test
    fun `no body and an empty body are different requests`() {
        assertNull(request().toFfi().body, "a GET without a body sends none at all")

        val empty = request { post(ScionHttp3RequestBody.empty()) }.toFfi().body
        assertArrayEquals(ByteArray(0), empty, "an empty body is a body, and says content-length 0")
    }

    @Test
    fun `header order and repetition survive`() {
        val ffi =
            request {
                addHeader("accept", "application/json")
                addHeader("x-trace", "1")
                addHeader("x-trace", "2")
            }.toFfi()

        assertEquals(
            listOf(
                Header("accept", "application/json"),
                Header("x-trace", "1"),
                Header("x-trace", "2"),
            ),
            ffi.headers,
            "merging repeated header lines would change what the peer receives",
        )
    }

    @Test
    fun `a body's media type is sent unless the caller set one`() {
        val implied = request { post(ScionHttp3RequestBody.json("{}")) }.toFfi()
        assertEquals(listOf(Header("content-type", "application/json")), implied.headers)

        val explicit =
            request {
                post(ScionHttp3RequestBody.json("{}"))
                header("content-type", "application/vnd.example+json")
            }.toFfi()
        assertEquals(
            listOf(Header("content-type", "application/vnd.example+json")),
            explicit.headers,
            "a caller who set the type meant it",
        )
    }

    @Test
    fun `a target is sent without a port, and the URL keeps its own`() {
        val ffi =
            request(url = "https://chat.example.org:54321/rooms") {
                target(ScionAddress.parse("1-ff00:0:110,10.0.0.1"))
            }.toFfi()

        assertEquals(listOf("1-ff00:0:110,10.0.0.1"), ffi.targets)
        assertEquals("https://chat.example.org:54321/rooms", ffi.url)
    }

    @Test
    fun `several targets are offered together`() {
        val ffi =
            request {
                target(ScionAddress.parse("1-ff00:0:110,10.0.0.1"))
                target(ScionAddress.parse("1-ff00:0:110,10.0.0.2"))
            }.toFfi()

        assertEquals(listOf("1-ff00:0:110,10.0.0.1", "1-ff00:0:110,10.0.0.2"), ffi.targets)
    }

    @Test
    fun `the per-request overrides are absent unless set`() {
        val plain = request().toFfi()
        assertNull(plain.requestTimeoutMs)
        assertNull(plain.maxResponseBodyBytes)

        val overridden =
            request {
                requestTimeoutMillis(60_000)
                maxResponseBody(1_024)
            }.toFfi()
        assertEquals(60_000uL, overridden.requestTimeoutMs)
        assertEquals(1_024uL, overridden.maxResponseBodyBytes)
    }

    @Test
    fun `the method crosses verbatim`() {
        assertEquals("GET", request().toFfi().method)
        assertEquals("PATCH", request { patch(ScionHttp3RequestBody.json("{}")) }.toFfi().method)
        assertEquals("REPORT", request { method("REPORT") }.toFfi().method)
    }

    @Test
    fun `a plaintext URL is refused where it was written`() {
        val failure =
            assertThrows<IllegalArgumentException> {
                ScionHttp3Request.Builder().url("http://example.org/x").build()
            }
        assertEquals(true, failure.message!!.contains("nothing to fall back to"))
    }

    @Test
    fun `a URL that is not absolute is refused`() {
        assertThrows<IllegalArgumentException> { ScionHttp3Request.Builder().url("/rooms").build() }
        assertThrows<IllegalArgumentException> {
            ScionHttp3Request
                .Builder()
                .url(
                    "https://",
                ).build()
        }
        assertThrows<IllegalArgumentException> { ScionHttp3Request.Builder().build() }
    }

    @Test
    fun `a method that is not a token is refused`() {
        assertThrows<IllegalArgumentException> { request { method("not a method") } }
        assertThrows<IllegalArgumentException> { request { method("") } }
    }

    @Test
    fun `a header that would break the header section is refused`() {
        assertThrows<IllegalArgumentException> { request { addHeader("x-bad\nname", "value") } }
        assertThrows<IllegalArgumentException> { request { addHeader("x-name", "line\r\nbreak") } }
        assertThrows<IllegalArgumentException> { request { addHeader("", "value") } }
    }

    @Test
    fun `a request body is copied, so a caller cannot change it afterwards`() {
        val bytes = "one".toByteArray()
        val body = ScionHttp3RequestBody.bytes(bytes)
        bytes[0] = 'X'.code.toByte()

        assertArrayEquals("one".toByteArray(), body.bytes())
    }

    @Test
    fun `a request can be sent twice, but a call cannot`(): Unit =
        kotlinx.coroutines.runBlocking {
            val factory = FakeBackendFactory()
            val client = client(factory = factory)
            val request = request()

            client.newCall(request).execute()
            client.newCall(request).execute()
            assertEquals(2, factory.backend.requests.size)

            val call = client.newCall(request)
            call.execute()
            assertThrows<IllegalStateException> {
                kotlinx.coroutines.runBlocking { call.execute() }
            }
        }

    @Test
    fun `a reused builder does not carry the previous body's media type`() {
        val builder = ScionHttp3Request.Builder().url("https://example.org/x")

        val posted = builder.post(ScionHttp3RequestBody.json("{}")).build()
        val plain = builder.get().build()

        assertEquals("application/json", posted.headers["content-type"])
        assertNull(
            plain.headers["content-type"],
            "a GET with no body must not describe the body of the request built before it",
        )
    }

    @Test
    fun `a reused builder does not accumulate the same media type twice`() {
        val builder = ScionHttp3Request.Builder().url("https://example.org/x")

        builder.post(ScionHttp3RequestBody.json("{}")).build()
        val second = builder.post(ScionHttp3RequestBody.json("{}")).build()

        assertEquals(listOf("application/json"), second.headers.values("content-type"))
    }

    @Test
    fun `a header value the stack cannot carry unchanged is refused`() {
        // Allowed by RFC 9110, but a value crosses the FFI as a UTF-8 string, so this byte would
        // arrive re-encoded as two.
        val failure =
            assertThrows<IllegalArgumentException> {
                request { addHeader("x-name", "caf\u00E9") }
            }
        assertTrue(failure.message!!.contains("ASCII"))
    }

    @Test
    fun `deriving a request from another keeps what was not changed`() {
        val original =
            request(url = "https://example.org/a") {
                addHeader("accept", "application/json")
                requestTimeoutMillis(1_000)
            }

        val derived = original.newBuilder().url("https://example.org/b").build()

        assertEquals("https://example.org/b", derived.url)
        assertEquals("application/json", derived.headers["accept"])
        assertEquals(1_000, derived.requestTimeoutMillis)
    }
}

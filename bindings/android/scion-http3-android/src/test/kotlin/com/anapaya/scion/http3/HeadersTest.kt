// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/** The small data structure the request and response surfaces both stand on. */
class HeadersTest {
    @Test
    fun `a name is found whatever case it was written in`() {
        val headers = ScionHttp3Headers.of("Content-Type" to "application/json")

        assertEquals("application/json", headers["content-type"])
        assertEquals("application/json", headers["CONTENT-TYPE"])
        assertTrue("Content-Type" in headers)
        assertFalse("content-length" in headers)
        assertNull(headers["content-length"])
    }

    @Test
    fun `a repeated name keeps every value, in order`() {
        val headers =
            ScionHttp3Headers
                .Builder()
                .add("set-cookie", "a=1")
                .add("set-cookie", "b=2")
                .build()

        assertEquals(listOf("a=1", "b=2"), headers.values("set-cookie"))
        assertEquals("a=1", headers["set-cookie"], "the first, and never a joining of the two")
        assertEquals(2, headers.size)
    }

    @Test
    fun `set replaces every line with that name`() {
        val headers =
            ScionHttp3Headers
                .Builder()
                .add("x-trace", "1")
                .add("accept", "*/*")
                .add("x-trace", "2")
                .set("X-Trace", "3")
                .build()

        assertEquals(listOf("3"), headers.values("x-trace"))
        assertEquals("*/*", headers["accept"])
    }

    @Test
    fun `removeAll is case-insensitive`() {
        val headers =
            ScionHttp3Headers
                .Builder()
                .add("x-trace", "1")
                .add("X-TRACE", "2")
                .removeAll("x-trace")
                .build()

        assertEquals(0, headers.size)
    }

    @Test
    fun `the names are the distinct ones, lower-cased, in the order they appeared`() {
        val headers =
            ScionHttp3Headers
                .Builder()
                .add("Accept", "*/*")
                .add("X-Trace", "1")
                .add("accept", "text/plain")
                .build()

        assertEquals(setOf("accept", "x-trace"), headers.names)
    }

    @Test
    fun `a section iterates in the order it was built`() {
        val headers = ScionHttp3Headers.of("b" to "2", "a" to "1", "b" to "3")

        assertEquals(
            listOf("b: 2", "a: 1", "b: 3"),
            headers.map { "${it.name}: ${it.value}" },
        )
    }

    @Test
    fun `deriving a section from another leaves the original alone`() {
        val original = ScionHttp3Headers.of("accept" to "*/*")

        val derived = original.newBuilder().add("x-trace", "1").build()

        assertEquals(1, original.size)
        assertEquals(2, derived.size)
    }

    @Test
    fun `a name or value that would break the section is refused`() {
        val builder = ScionHttp3Headers.Builder()

        assertThrows<IllegalArgumentException> { builder.add("", "value") }
        assertThrows<IllegalArgumentException> { builder.add("x name", "value") }
        assertThrows<IllegalArgumentException> { builder.add("x:name", "value") }
        assertThrows<IllegalArgumentException> { builder.add("x-name", "line\nbreak") }
        assertThrows<IllegalArgumentException> { builder.add("x-name", "carriage\rreturn") }
    }

    @Test
    fun `the symbols a header name may hold are allowed`() {
        ScionHttp3Headers.Builder().add("x-name_1.2*", "value").build()
    }

    @Test
    fun `two sections with the same lines in the same order are equal`() {
        assertEquals(
            ScionHttp3Headers.of("a" to "1", "b" to "2"),
            ScionHttp3Headers.of("a" to "1", "b" to "2"),
        )
        assertFalse(
            ScionHttp3Headers.of("a" to "1", "b" to "2") ==
                ScionHttp3Headers.of("b" to "2", "a" to "1"),
        )
    }

    @Test
    fun `the empty section holds nothing`() {
        assertEquals(0, ScionHttp3Headers.EMPTY.size)
        assertTrue(ScionHttp3Headers.EMPTY.names.isEmpty())
    }
}

// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.InetAddress
import java.net.InetSocketAddress

class AuthorityTest {
    @Test
    fun `a host and a port make an authority, lowercased`() {
        val authority = ScionHttp3Authority(" Chat.Example.org ", 5222)

        assertEquals("chat.example.org", authority.host)
        assertEquals(5222, authority.port)
        assertEquals("chat.example.org:5222", authority.toString())
    }

    @Test
    fun `an IPv6 literal is bracketed and loses its scope`() {
        assertEquals("[fe80::1]:443", ScionHttp3Authority("fe80::1%wlan0", 443).toString())
        assertEquals("[::1]:443", ScionHttp3Authority("[::1]", 443).toString())
        assertEquals("[::]:443", ScionHttp3Authority("::", 443).toString())
        assertEquals("[2001:db8::1]:443", ScionHttp3Authority("2001:DB8::1", 443).toString())
        assertEquals(
            "[1:2:3:4:5:6:7:8]:443",
            ScionHttp3Authority("1:2:3:4:5:6:7:8", 443).toString(),
        )
        assertEquals(
            "[::ffff:10.0.0.1]:443",
            ScionHttp3Authority("::ffff:10.0.0.1", 443).toString(),
        )
        assertEquals(
            "[1:2:3:4:5:6:10.0.0.1]:443",
            ScionHttp3Authority("1:2:3:4:5:6:10.0.0.1", 443).toString(),
        )
        assertEquals("10.0.0.1:443", ScionHttp3Authority("10.0.0.1", 443).toString())
    }

    @Test
    fun `a colon in anything but an IPv6 literal is refused, as the stack refuses it`() {
        listOf(
            "a:b",
            "[a:b]",
            ":::1",
            "1:2:3:4:5:6:7:8:9",
            "1:2:3:4:5:6:7",
            "12345::1",
            "1::2::3",
            ":",
            "::1.2.3",
            "::10.0.0.256",
        ).forEach { assertThrows<IllegalArgumentException>(it) { ScionHttp3Authority(it, 443) } }
    }

    @Test
    fun `the text form parses back, and only with a port`() {
        assertEquals(
            ScionHttp3Authority("chat.example.org", 5222),
            ScionHttp3Authority.parse("chat.example.org:5222"),
        )
        assertEquals(ScionHttp3Authority("::1", 443), ScionHttp3Authority.parse("[::1]:443"))

        listOf(
            "chat.example.org",
            "[::1]",
            "chat.example.org:",
            "chat.example.org:port",
            ":5222",
        ).forEach {
            assertThrows<IllegalArgumentException>(it) { ScionHttp3Authority.parse(it) }
        }
    }

    @Test
    fun `what the stack would refuse is refused here`() {
        assertThrows<IllegalArgumentException> { ScionHttp3Authority("chat.example.org", 0) }
        assertThrows<IllegalArgumentException> { ScionHttp3Authority("chat.example.org", 65536) }
        assertThrows<IllegalArgumentException> { ScionHttp3Authority("", 5222) }
        assertThrows<IllegalArgumentException> {
            ScionHttp3Authority(
                "user@chat.example.org",
                5222,
            )
        }
        assertThrows<IllegalArgumentException> {
            ScionHttp3Authority(
                "chat.example.org/path",
                5222,
            )
        }
        assertThrows<IllegalArgumentException> { ScionHttp3Authority("chat example.org", 5222) }
        assertThrows<IllegalArgumentException> { ScionHttp3Authority("[::1", 443) }
        assertThrows<IllegalArgumentException> { ScionHttp3Authority("[::1]x", 443) }
    }

    @Test
    fun `an endpoint keeps the name it was created with, or gives its address`() {
        val named =
            InetSocketAddress(
                InetAddress.getByAddress("chat.example.org", bytesOf(10, 0, 0, 1)),
                443,
            )
        assertEquals("chat.example.org:443", ScionHttp3Authority.of(named).toString())

        val bare = InetSocketAddress(InetAddress.getByAddress(bytesOf(10, 0, 0, 1)), 443)
        assertEquals("10.0.0.1:443", ScionHttp3Authority.of(bare).toString())

        val unresolved = InetSocketAddress.createUnresolved("chat.example.org", 5222)
        assertEquals("chat.example.org:5222", ScionHttp3Authority.of(unresolved).toString())
    }

    @Test
    fun `equality is by host and port`() {
        assertEquals(
            ScionHttp3Authority("A.example.org", 1),
            ScionHttp3Authority("a.example.org", 1),
        )
        assertEquals(
            ScionHttp3Authority("a.example.org", 1).hashCode(),
            ScionHttp3Authority("a.example.org", 1).hashCode(),
        )
        assertNotEquals(
            ScionHttp3Authority("a.example.org", 1),
            ScionHttp3Authority("a.example.org", 2),
        )
    }
}

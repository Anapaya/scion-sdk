// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3

import com.anapaya.scion.http3.internal.NetworkIdentity
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/**
 * The one type in the request path that names a SCION concept, and the address normalization the
 * staleness decision rests on.
 *
 * Only the shape of an address is checked. Whether it exists is the stack's judgement, and this
 * deliberately does not try to have an opinion about SCION topology.
 */
class ScionAddressTest {
    @Test
    fun `an address keeps the text it was given`() {
        assertEquals(
            "1-ff00:0:110,10.0.0.1",
            ScionAddress.parse("1-ff00:0:110,10.0.0.1").toString(),
        )
        assertEquals(
            "1-ff00:0:110,[::1]",
            ScionAddress.parse("  1-ff00:0:110,[::1]  ").toString(),
            "surrounding space is a copy-paste artefact, not part of the address",
        )
    }

    @Test
    fun `an IPv6 host is allowed, bracketed or not`() {
        ScionAddress.parse("1-ff00:0:110,[2001:db8::1]")
        ScionAddress.parse("1-ff00:0:110,2001:db8::1")
    }

    @Test
    fun `a port is refused, and the message says where the port belongs`() {
        val failure =
            assertThrows<IllegalArgumentException> {
                ScionAddress.parse("1-ff00:0:110,10.0.0.1:443")
            }
        assertTrue(failure.message!!.contains("the port comes from the request URL"))

        assertThrows<IllegalArgumentException> { ScionAddress.parse("1-ff00:0:110,[::1]:443") }
        assertThrows<IllegalArgumentException> {
            // No dot in sight, so a heuristic looking for one would let this through.
            ScionAddress.parse("1-ff00:0:110,localhost:8080")
        }
    }

    @Test
    fun `an IPv4-mapped IPv6 host is not a port`() {
        // Colons and dots together, which is exactly what a dot-based heuristic mistakes for a port.
        ScionAddress.parse("1-ff00:0:110,::ffff:10.0.0.1")
        ScionAddress.parse("1-ff00:0:110,[::ffff:10.0.0.1]")
    }

    @Test
    fun `something that is not an address at all is refused`() {
        assertThrows<IllegalArgumentException> { ScionAddress.parse("") }
        assertThrows<IllegalArgumentException> { ScionAddress.parse("10.0.0.1") }
        assertThrows<IllegalArgumentException> { ScionAddress.parse("1-ff00:0:110") }
        assertThrows<IllegalArgumentException> { ScionAddress.parse("1-ff00:0:110,") }
        assertThrows<IllegalArgumentException> { ScionAddress.parse(",10.0.0.1") }
        assertThrows<IllegalArgumentException> { ScionAddress.parse("ff00:0:110,10.0.0.1") }
        assertThrows<IllegalArgumentException> { ScionAddress.parse("1-ff00:0:110,[::1") }
    }

    @Test
    fun `two addresses with the same text are the same address`() {
        assertEquals(
            ScionAddress.parse("1-ff00:0:110,10.0.0.1"),
            ScionAddress.parse("1-ff00:0:110,10.0.0.1"),
        )
        assertNotEquals(
            ScionAddress.parse("1-ff00:0:110,10.0.0.1"),
            ScionAddress.parse("1-ff00:0:110,10.0.0.2"),
        )
    }

    @Test
    fun `an IPv4 address normalizes to itself and its prefix`() {
        assertEquals(
            "192.168.1.10/24",
            NetworkIdentity.normalizeAddress(bytesOf(192, 168, 1, 10), 24),
        )
    }

    @Test
    fun `an IPv4 link-local address says nothing about which network this is`() {
        assertNull(
            NetworkIdentity.normalizeAddress(bytesOf(169, 254, 1, 5), 16),
            "it is what the platform assigns when it has no address, and it comes and goes on its own",
        )
    }

    @Test
    fun `an IPv6 address is reduced to its prefix`() {
        val first = ipv6("20010db8000000000000000000000001", prefix = 64)
        val second = ipv6("20010db8000000001122334455667788", prefix = 64)

        assertEquals(
            first,
            second,
            "Android rotates privacy addresses inside one prefix, and a rotation invalidates " +
                "nothing: keeping the host bits would rebuild everything every time",
        )
        assertNotEquals(first, ipv6("20010db8000000010000000000000001", prefix = 64))
    }

    @Test
    fun `an IPv6 link-local address is ignored`() {
        assertNull(NetworkIdentity.normalizeAddress(hex("fe800000000000000000000000000001"), 64))
    }

    private fun ipv6(
        hex: String,
        prefix: Int,
    ): String? = NetworkIdentity.normalizeAddress(hex(hex), prefix)

    private fun hex(hex: String): ByteArray =
        ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}

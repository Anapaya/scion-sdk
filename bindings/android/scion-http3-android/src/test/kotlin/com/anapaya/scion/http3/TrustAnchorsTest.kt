// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3

import com.anapaya.scion.http3.internal.AndroidSystemTrustStore
import com.anapaya.scion.http3.internal.CachingTrustStore
import com.anapaya.scion.http3.internal.PemEncoder
import com.anapaya.scion.http3.internal.SystemTrustStore
import com.anapaya.scion.http3.internal.toFfi
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import com.anapaya.scion.http3.uniffi.TrustAnchors as FfiTrustAnchors

/**
 * How trust anchors reach the TLS stack.
 *
 * The wiring here has the widest blast radius of anything in the library: handing down the FFI's own
 * "system default" configures no anchors at all on Android, and every handshake then fails; producing
 * a bundle the parser rejects fails them all in the same way, and neither failure says anything about
 * anchors when it surfaces.
 *
 * Most of this runs the production code unchanged, which is the point of reading the anchors through
 * `TrustManagerFactory`: it is plain JDK API, so on a desktop JVM it yields that JVM's own
 * authorities and the same code path can be exercised without a device.
 */
class TrustAnchorsTest {
    @Test
    fun `the platform anchors become an in-memory bundle, never the stack's system default`() {
        val store = FakeTrustStore(validPem)

        val ffi = TrustAnchors.systemDefault().toFfi(store)

        val pem = assertInstanceOf(FfiTrustAnchors.Pem::class.java, ffi)
        assertArrayEquals(validPem, pem.pem)
        assertEquals(
            1,
            store.reads.get(),
            "the anchors live in a keystore the TLS stack cannot read, so they are read here " +
                "and passed down as bytes",
        )
    }

    @Test
    fun `pinned anchors are passed down exactly as given`() {
        val ffi = TrustAnchors.pinned(validPem).toFfi(FakeTrustStore())

        val pem = assertInstanceOf(FfiTrustAnchors.Pem::class.java, ffi)
        assertArrayEquals(validPem, pem.pem, "a bundle's contents and order are the caller's")
    }

    @Test
    fun `pinned anchors are copied, so a caller cannot change them afterwards`() {
        val bundle = validPem.copyOf()
        val anchors = TrustAnchors.pinned(bundle)

        bundle[0] = 'X'.code.toByte()

        val pem = assertInstanceOf(FfiTrustAnchors.Pem::class.java, anchors.toFfi(FakeTrustStore()))
        assertArrayEquals(validPem, pem.pem)
    }

    @Test
    fun `disabled verification is passed down as such`() {
        assertInstanceOf(
            FfiTrustAnchors.InsecureNoVerify::class.java,
            TrustAnchors.insecureNoVerify().toFfi(FakeTrustStore()),
        )
    }

    @Test
    fun `a bundle with no certificate in it is refused at the call that supplied it`() {
        // Nothing at all, and a bundle whose blocks hold nothing, both parse to no certificates.
        val empty = assertThrows<IllegalArgumentException> { TrustAnchors.pinned(ByteArray(0)) }
        assertTrue(empty.message!!.contains("no certificate"))
        assertTrue(
            empty.message!!.contains("BEGIN CERTIFICATE"),
            "the message says what a bundle is expected to look like",
        )

        // Where the parser objects instead, its complaint is carried rather than replaced.
        val garbage =
            assertThrows<IllegalArgumentException> {
                TrustAnchors.pinned("-----BEGIN NOTHING-----\n".toByteArray())
            }
        assertTrue(garbage.message!!.contains("not a readable PEM bundle"))
        assertThrows<IllegalArgumentException> { TrustAnchors.pinned("not a bundle".toByteArray()) }
    }

    @Test
    fun `the anchors are read once per process`() {
        val underlying = FakeTrustStore(validPem)
        val store = CachingTrustStore(underlying)

        val first = store.anchorsPem()
        val second = store.anchorsPem()

        assertEquals(
            1,
            underlying.reads.get(),
            "a few hundred certificates is not a per-client cost",
        )
        assertArrayEquals(first, second)
    }

    @Test
    fun `a platform with no anchors at all is an error rather than an empty bundle`() {
        val store = CachingTrustStore(SystemTrustStore { ByteArray(0) })

        // The library's own exception, not an IllegalStateException: the anchors are read while a
        // request builds connectivity, so this reaches a caller through a request and has to be an
        // IOException like every other way one can fail.
        val failure = assertThrows<ScionHttp3Exception.Connectivity> { store.anchorsPem() }

        assertTrue(
            failure.detail.contains("TrustAnchors.pinned()"),
            "an empty bundle would accept nothing, and fail every handshake without saying why",
        )
        assertFalse(failure.isRetryable, "the same platform will report the same nothing again")
    }

    @Test
    fun `the bundle is laid out the way the parser below expects`() {
        val text = String(PemEncoder.encode(platformAnchors()), Charsets.US_ASCII)

        val lines = text.lines().dropLast(1)
        assertTrue(lines.first() == "-----BEGIN CERTIFICATE-----")
        assertTrue(lines.last() == "-----END CERTIFICATE-----")
        assertTrue(
            lines.none { it.length > 64 },
            "a line over 64 characters makes the parser reject the whole bundle, not one entry",
        )
        assertTrue(
            text.contains("\n-----END CERTIFICATE-----\n"),
            "the line break before the end marker is what a hand-rolled encoder forgets",
        )
    }

    @Test
    fun `the bundle holds every certificate it was given, unchanged`() {
        val anchors = platformAnchors()

        val decoded =
            CertificateFactory
                .getInstance("X.509")
                .generateCertificates(ByteArrayInputStream(PemEncoder.encode(anchors)))
                .filterIsInstance<X509Certificate>()

        assertEquals(
            anchors.map { it.subjectX500Principal },
            decoded.map { it.subjectX500Principal },
            "round-tripping is the assertion: comparing against a stored fixture would only " +
                "prove the fixture was generated by this encoder",
        )
    }

    @Test
    fun `an empty list encodes to an empty bundle`() {
        assertArrayEquals(ByteArray(0), PemEncoder.encode(emptyList()))
    }

    @Test
    fun `the platform's own trust manager is where the anchors come from`() {
        val pem = AndroidSystemTrustStore().anchorsPem()

        assertTrue(pem.isNotEmpty())
        assertTrue(
            String(pem, Charsets.US_ASCII).startsWith("-----BEGIN CERTIFICATE-----"),
            "this is the production path, running unchanged: reading the anchors through " +
                "TrustManagerFactory is plain JDK API, which is why it can be tested here at all",
        )
    }
}

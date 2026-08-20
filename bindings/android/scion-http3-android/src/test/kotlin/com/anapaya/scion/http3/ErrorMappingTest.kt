// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3

import com.anapaya.scion.http3.internal.toPublic
import com.anapaya.scion.http3.uniffi.TimeoutPhase
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.IOException
import com.anapaya.scion.http3.uniffi.ScionHttp3Exception as FfiException

/**
 * That every failure the stack can report becomes the right public one.
 *
 * Not every public arm has a counterpart: [ScionHttp3Exception.InvalidBody] is raised here rather
 * than below, by a body that will not decode as UTF-8, and the stack has no arm for it because it
 * never decodes one. ResponseTest covers that arm.
 *
 * Written as a table rather than as a test per arm. The compiler already makes the mapping
 * exhaustive, so a test per arm would mostly restate the code; what it cannot check is that an arm is
 * wired to the *right* counterpart, and the table does that in one place. The invariants below the
 * table are the part worth spelling out, because they are properties of the mapping rather than of
 * any one arm.
 */
class ErrorMappingTest {
    private val everyArm: List<Pair<FfiException, Class<out ScionHttp3Exception>>> =
        listOf(
            FfiException.StackBuild(true, "d") to ScionHttp3Exception.Connectivity::class.java,
            FfiException.Resolution("h", false, "d") to ScionHttp3Exception.Resolution::class.java,
            FfiException.Connect("h", 443u, true, "d") to ScionHttp3Exception.Connect::class.java,
            FfiException.Tls("h", false, "d") to ScionHttp3Exception.Tls::class.java,
            FfiException.StreamReset(258uL, true, "d") to
                ScionHttp3Exception.StreamReset::class.java,
            FfiException.Protocol(false, "d") to ScionHttp3Exception.Protocol::class.java,
            FfiException.ConnectionLimit(true, "d") to
                ScionHttp3Exception.ConnectionLimit::class.java,
            FfiException.BodyTooLarge(1_024uL, false, "d") to
                ScionHttp3Exception.BodyTooLarge::class.java,
            FfiException.Timeout(TimeoutPhase.REQUEST, 30_000uL, true, "d") to
                ScionHttp3Exception.Timeout::class.java,
            FfiException.InvalidRequest(false, "d") to
                ScionHttp3Exception.InvalidRequest::class.java,
            FfiException.Closed(false, "d") to ScionHttp3Exception.Closed::class.java,
            FfiException.Internal(false, "d") to ScionHttp3Exception.Internal::class.java,
        )

    @Test
    fun `each failure from the stack becomes its counterpart`() {
        everyArm.forEach { (ffi, expected) ->
            assertInstanceOf(
                expected,
                ffi.toPublic(),
                "${ffi::class.simpleName} was mapped wrongly",
            )
        }
    }

    @Test
    fun `every failure the stack can report is mapped`() {
        val mapped = everyArm.map { it.first::class.simpleName }.toSet()
        // Java reflection, not Kotlin's sealedSubclasses: that needs kotlin-reflect on the
        // classpath, which is a dependency this tier does not otherwise need.
        val declared =
            FfiException::class.java.declaredClasses
                .filter { FfiException::class.java.isAssignableFrom(it) }
                .map { it.simpleName }
                .toSet()

        assertEquals(
            declared,
            mapped,
            "an arm added to the FFI is a compilation error in the mapping, and this makes it a " +
                "test failure here as well",
        )
    }

    @Test
    fun `everything a request can fail with is an IOException`() {
        everyArm.forEach { (ffi, _) ->
            assertInstanceOf(
                IOException::class.java,
                ffi.toPublic(),
                "an application already handles network failure; these must fit that handling",
            )
        }
    }

    @Test
    fun `retryability and detail come from the stack, not from the arm`() {
        val retryable =
            FfiException
                .Tls(
                    "h",
                    true,
                    "unusually, this one is worth retrying",
                ).toPublic()
        assertTrue(
            retryable.isRetryable,
            "whether a retry can help depends on what failed, which the stack knows and the arm " +
                "does not",
        )
        assertEquals("unusually, this one is worth retrying", retryable.detail)

        assertFalse(FfiException.ConnectionLimit(false, "d").toPublic().isRetryable)
    }

    @Test
    fun `the original failure is kept as the cause`() {
        val ffi = FfiException.Protocol(false, "malformed frame")
        assertSame(ffi, ffi.toPublic().cause)
    }

    @Test
    fun `what each arm carries survives the crossing`() {
        val resolution = FfiException.Resolution("chat.example.org", false, "d").toPublic()
        assertEquals("chat.example.org", (resolution as ScionHttp3Exception.Resolution).host)

        val connect = FfiException.Connect("chat.example.org", 8443u, true, "d").toPublic()
        assertEquals(8443, (connect as ScionHttp3Exception.Connect).port)

        val reset = FfiException.StreamReset(258uL, true, "d").toPublic()
        assertEquals(258L, (reset as ScionHttp3Exception.StreamReset).code)

        val tooLarge = FfiException.BodyTooLarge(16_777_216uL, false, "d").toPublic()
        assertEquals(16_777_216L, (tooLarge as ScionHttp3Exception.BodyTooLarge).limit)

        val timeout = FfiException.Timeout(TimeoutPhase.BODY, 5_000uL, true, "d").toPublic()
        assertEquals(
            ScionHttp3Exception.TimeoutPhase.BODY,
            (timeout as ScionHttp3Exception.Timeout).phase,
        )
        assertEquals(5_000L, timeout.timeoutMillis)
    }

    @Test
    fun `every timeout phase has a counterpart`() {
        TimeoutPhase.entries.forEach { phase ->
            val mapped = FfiException.Timeout(phase, 1uL, false, "d").toPublic()
            assertEquals(
                phase.name,
                (mapped as ScionHttp3Exception.Timeout).phase.name,
                "the two enumerations are kept in step by name, so a new phase is caught here",
            )
        }
    }

    @Test
    fun `the message says something useful rather than repeating the fields`() {
        val connect = FfiException.Connect("chat.example.org", 443u, true, "no route").toPublic()
        assertEquals("chat.example.org:443: no route", connect.message)

        val timeout =
            FfiException
                .Timeout(
                    TimeoutPhase.CONNECT,
                    10_000uL,
                    true,
                    "gave up",
                ).toPublic()
        assertEquals("timed out after 10000ms in CONNECT: gave up", timeout.message)
    }
}

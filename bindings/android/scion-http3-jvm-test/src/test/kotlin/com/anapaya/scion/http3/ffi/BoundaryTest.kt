// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.ffi

import com.anapaya.scion.http3.uniffi.internalPanicForTest
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.util.concurrent.TimeUnit

/**
 * What the FFI boundary itself guarantees, independently of any call made across it.
 *
 * Needs no server and no client: it is about the shape of the boundary rather than about anything
 * reached through it.
 */
@Timeout(value = 1, unit = TimeUnit.MINUTES)
class BoundaryTest {
    /**
     * A Rust panic has to arrive as an exception rather than as a dead process.
     *
     * The crate refuses to compile under `panic = "abort"` for exactly this, and nothing in the API
     * panics on purpose, so it exports a function that does. If this test ever kills the JVM instead
     * of failing, the profile the library was built with is wrong.
     */
    @Test
    fun `a panic in Rust crosses the boundary as an exception`() {
        val thrown = runCatching { internalPanicForTest() }.exceptionOrNull()
        assertTrue(thrown != null, "the panic did not surface at all")
        assertTrue(
            thrown.toString().contains("deliberate panic"),
            "the panic surfaced without its message: $thrown",
        )
    }
}

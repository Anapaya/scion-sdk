// Copyright 2026 Anapaya Systems

package net.anapaya.ktor.scion

/**
 * Prepares the platform verifier of the Rust library. Call it before the
 * first engine is built.
 */
internal expect fun initPlatformTrust()

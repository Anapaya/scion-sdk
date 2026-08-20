// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3

import com.anapaya.scion.http3.internal.ClientSettings
import com.anapaya.scion.http3.internal.applyTo
import com.anapaya.scion.http3.uniffi.ClientConfig
import com.anapaya.scion.http3.uniffi.DiscoveryConfig
import com.anapaya.scion.http3.uniffi.Underlay
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import com.anapaya.scion.http3.uniffi.SnapConfig as FfiSnapConfig
import com.anapaya.scion.http3.uniffi.TrustAnchors as FfiTrustAnchors
import com.anapaya.scion.http3.uniffi.UdpConfig as FfiUdpConfig

/**
 * That every setting lands in the field it belongs in.
 *
 * Written as one comparison of the whole configuration rather than as a test per field. Both catch a
 * setting reaching the wrong field, which is the bug worth catching here, since the timeouts are all
 * the same type and one of them is a copy-paste away from being another. The whole-object form also
 * cannot be satisfied by restating the mapping, which a field-by-field test is: it fails when a
 * setting is applied that should not be, not only when one is missing.
 *
 * The base configuration stands in for what the stack's own `defaultClientConfig()` returns. It is
 * built by hand here on purpose: calling the real one would load the native library, and this tier
 * has none.
 */
class ConfigMappingTest {
    private val base =
        ClientConfig(
            endhostApiUrl = "https://placeholder.invalid",
            authToken = null,
            preferredUnderlay = null,
            discovery = DiscoveryConfig(),
            snap = FfiSnapConfig(),
            udp = FfiUdpConfig(),
            trust = FfiTrustAnchors.SystemDefault,
            connectTimeoutMs = 10_000u,
            requestTimeoutMs = 30_000u,
            idleConnectionTimeoutMs = 25_000u,
            maxOrigins = 8u,
            connectionAttemptDelayMs = 250u,
            maxResponseBodyBytes = 16u * 1024u * 1024u,
        )

    @Test
    fun `every setting crosses into the field it belongs in`() {
        val settings =
            ClientSettings(
                endhostApiUrl = "https://endhost-api.example.org",
                trust = TrustAnchors.insecureNoVerify(),
                authToken = "a-token",
                preferredUnderlay = PreferredUnderlay.SNAP,
                snap = SnapConfig.Builder().dataPlaneIndex(3).build(),
                udp = UdpConfig.Builder().outboundIps(listOf("10.0.0.5")).build(),
                connectTimeoutMillis = 1_111,
                requestTimeoutMillis = 2_222,
                idleConnectionTimeoutMillis = 3_333,
                connectionAttemptDelayMillis = 444,
                maxOrigins = 5,
                maxResponseBodyBytes = 6_666,
            )

        val config = settings.applyTo(base, FfiTrustAnchors.InsecureNoVerify)

        assertEquals(
            base.copy(
                endhostApiUrl = "https://endhost-api.example.org",
                authToken = "a-token",
                preferredUnderlay = Underlay.SNAP,
                snap = FfiSnapConfig(dpIndex = 3u),
                udp = FfiUdpConfig(outboundIps = listOf("10.0.0.5")),
                trust = FfiTrustAnchors.InsecureNoVerify,
                connectTimeoutMs = 1_111u,
                requestTimeoutMs = 2_222u,
                idleConnectionTimeoutMs = 3_333u,
                maxOrigins = 5u,
                connectionAttemptDelayMs = 444u,
                maxResponseBodyBytes = 6_666u,
            ),
            config,
        )
    }

    @Test
    fun `an unset setting keeps the stack's own default`() {
        val config =
            ClientSettings(
                endhostApiUrl = "https://endhost-api.example.org",
                trust = TrustAnchors.systemDefault(),
            ).applyTo(base, FfiTrustAnchors.InsecureNoVerify)

        assertEquals(
            base.copy(
                endhostApiUrl = "https://endhost-api.example.org",
                trust = FfiTrustAnchors.InsecureNoVerify,
            ),
            config,
            "every default has one home, and it is the SCION stack. A value restated in Kotlin " +
                "would be a second copy that eventually disagrees.",
        )
    }

    @Test
    fun `durations cross as milliseconds`() {
        val config =
            ClientSettings(
                endhostApiUrl = "https://endhost-api.example.org",
                trust = TrustAnchors.systemDefault(),
                requestTimeoutMillis = 90_000,
            ).applyTo(base, FfiTrustAnchors.InsecureNoVerify)

        assertEquals(90_000uL, config.requestTimeoutMs)
    }

    @Test
    fun `a SNAP static identity crosses as its 32 bytes`() {
        val key = ByteArray(32) { it.toByte() }
        val config =
            ClientSettings(
                endhostApiUrl = "https://endhost-api.example.org",
                trust = TrustAnchors.systemDefault(),
                snap = SnapConfig.Builder().staticIdentity(key).build(),
            ).applyTo(base, FfiTrustAnchors.InsecureNoVerify)

        assertArrayEquals(key, config.snap.staticIdentity)
    }
}

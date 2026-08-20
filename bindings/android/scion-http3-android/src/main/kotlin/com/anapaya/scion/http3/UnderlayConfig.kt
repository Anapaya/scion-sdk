// Copyright 2026 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.anapaya.scion.http3

import kotlin.time.Duration

/**
 * Which transport to prefer for carrying traffic.
 *
 * A preference, not a choice: the endhost API decides what is available, and this says which to
 * favour among what it returns. An application that does not care should not set it.
 */
public enum class PreferredUnderlay {
    SNAP,
    UDP,
}

/**
 * Settings for the SNAP transport.
 *
 * Every setting is optional, and an unset one keeps whatever the SCION stack defaults to rather
 * than a value restated here.
 */
public class SnapConfig private constructor(
    internal val dataPlaneIndex: Int?,
    internal val staticIdentity: ByteArray?,
) {
    /** Accumulates SNAP settings. */
    public class Builder {
        private var dataPlaneIndex: Int? = null
        private var staticIdentity: ByteArray? = null

        /** Selects one of several data planes the endhost API offers. */
        public fun dataPlaneIndex(index: Int): Builder {
            require(index >= 0) { "a data plane index cannot be negative, got $index" }
            dataPlaneIndex = index
            return this
        }

        /**
         * A fixed 32-byte X25519 private key identifying this endpoint to the SNAP server.
         *
         * Without one, a fresh key is generated every time connectivity is established, and the
         * server sees a new endpoint each time. Since connectivity is re-established on every
         * network change, a mobile client changes identity often, which matters wherever the server
         * keeps per-endpoint state.
         *
         * @throws IllegalArgumentException unless [key] is exactly 32 bytes.
         */
        public fun staticIdentity(key: ByteArray): Builder {
            require(key.size == 32) {
                "a SNAP static identity is a 32-byte X25519 private key, got ${key.size} bytes"
            }
            staticIdentity = key.copyOf()
            return this
        }

        public fun build(): SnapConfig = SnapConfig(dataPlaneIndex, staticIdentity)
    }
}

/**
 * Settings for the plain UDP transport, for the rare case where its defaults do not fit.
 *
 * As with [SnapConfig], an unset setting keeps the stack's default.
 */
public class UdpConfig private constructor(
    internal val outboundIps: List<String>,
    internal val nextHopResolverFetchIntervalMillis: Long?,
) {
    /** Accumulates UDP settings. */
    public class Builder {
        private val outboundIps = mutableListOf<String>()
        private var nextHopResolverFetchIntervalMillis: Long? = null

        /**
         * Sends from these local addresses instead of letting the platform choose.
         *
         * Rarely useful on a mobile device, where the address changes with the network and is the
         * platform's to pick.
         */
        public fun outboundIps(ips: List<String>): Builder {
            require(ips.none { it.isBlank() }) { "an outbound IP cannot be blank" }
            outboundIps.clear()
            outboundIps += ips
            return this
        }

        /** How often to refresh the next-hop information the UDP transport routes by. */
        public fun nextHopResolverFetchInterval(interval: Duration): Builder =
            nextHopResolverFetchIntervalMillis(interval.inWholeMilliseconds)

        /** As [nextHopResolverFetchInterval], in milliseconds, for Java callers. */
        public fun nextHopResolverFetchIntervalMillis(millis: Long): Builder {
            require(millis > 0) { "a fetch interval must be positive, not $millis ms" }
            nextHopResolverFetchIntervalMillis = millis
            return this
        }

        public fun build(): UdpConfig =
            UdpConfig(outboundIps.toList(), nextHopResolverFetchIntervalMillis)
    }
}

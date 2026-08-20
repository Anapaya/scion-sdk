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

package com.anapaya.scion.http3.internal

import com.anapaya.scion.http3.ScionHttp3Exception
import java.security.cert.X509Certificate

/**
 * Turns certificates into the PEM bundle the TLS stack below reads.
 *
 * A bundle rather than a file: the platform keeps its trust anchors somewhere BoringSSL cannot look,
 * so they are read here and handed down in memory. Writing them to a temporary file would work and
 * would put trust material on disk for no reason.
 *
 * The layout is exact on purpose. A missing line break before the end marker, or a line longer than
 * 64 characters, makes the parser below reject the whole bundle rather than one certificate, and the
 * failure surfaces much later as an unexplained handshake error.
 */
internal object PemEncoder {
    private const val BEGIN = "-----BEGIN CERTIFICATE-----"
    private const val END = "-----END CERTIFICATE-----"
    private const val LINE_LENGTH = 64

    private val alphabet =
        ('A'..'Z').joinToString("") + ('a'..'z').joinToString("") + ('0'..'9').joinToString("") +
            "+/"

    /** Encodes every certificate in [certificates], in the order given. */
    fun encode(certificates: List<X509Certificate>): ByteArray {
        val text = StringBuilder()
        certificates.forEach { certificate ->
            text.append(BEGIN).append('\n')
            val base64 = base64(certificate.encoded)
            var offset = 0
            while (offset < base64.length) {
                val end = minOf(offset + LINE_LENGTH, base64.length)
                text.append(base64, offset, end).append('\n')
                offset = end
            }
            text.append(END).append('\n')
        }
        return text.toString().toByteArray(Charsets.US_ASCII)
    }

    /**
     * Base64, written out here rather than taken from a library.
     *
     * `java.util.Base64` needs API 26 and this library supports 24; `android.util.Base64` would put
     * a framework type in a file that is otherwise pure, which is what keeps this testable on a
     * desktop JVM. Kotlin's own encoder is still behind an opt-in at the version this builds with.
     */
    private fun base64(bytes: ByteArray): String {
        val out = StringBuilder((bytes.size + 2) / 3 * 4)
        var i = 0
        while (i + 2 < bytes.size) {
            val chunk =
                ((bytes[i].toInt() and 0xFF) shl 16) or
                    ((bytes[i + 1].toInt() and 0xFF) shl 8) or
                    (bytes[i + 2].toInt() and 0xFF)
            out.append(alphabet[(chunk shr 18) and 0x3F])
            out.append(alphabet[(chunk shr 12) and 0x3F])
            out.append(alphabet[(chunk shr 6) and 0x3F])
            out.append(alphabet[chunk and 0x3F])
            i += 3
        }
        when (bytes.size - i) {
            1 -> {
                val chunk = (bytes[i].toInt() and 0xFF) shl 16
                out.append(alphabet[(chunk shr 18) and 0x3F])
                out.append(alphabet[(chunk shr 12) and 0x3F])
                out.append("==")
            }
            2 -> {
                val chunk =
                    ((bytes[i].toInt() and 0xFF) shl 16) or ((bytes[i + 1].toInt() and 0xFF) shl 8)
                out.append(alphabet[(chunk shr 18) and 0x3F])
                out.append(alphabet[(chunk shr 12) and 0x3F])
                out.append(alphabet[(chunk shr 6) and 0x3F])
                out.append('=')
            }
        }
        return out.toString()
    }
}

/**
 * Reads the platform's trust anchors once and keeps them.
 *
 * Kept for the life of the process, and deliberately not invalidated by a network change or a
 * rebuild: trust anchors are not a property of the network. An authority installed while the process
 * runs is therefore not picked up, which is also what happens to any long-lived TLS context.
 */
internal class CachingTrustStore(
    private val delegate: SystemTrustStore,
) : SystemTrustStore {
    private val lock = Any()

    @Volatile
    private var cached: ByteArray? = null

    override fun anchorsPem(): ByteArray {
        cached?.let { return it }
        return synchronized(lock) {
            cached?.let { return it }
            val read = delegate.anchorsPem()
            // Reported as a connectivity failure rather than as an IllegalStateException: this is
            // reached from a request, and every failure a request can produce is an IOException.
            if (read.isEmpty()) {
                throw ScionHttp3Exception.Connectivity(
                    isRetryable = false,
                    detail =
                        "the platform reported no trust anchors, so no server certificate could " +
                            "be accepted. Pass the deployment's certificate authority to " +
                            "TrustAnchors.pinned() instead.",
                )
            }
            read.also { cached = it }
        }
    }
}

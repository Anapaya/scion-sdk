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

import java.io.ByteArrayInputStream
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory

/**
 * Which certificate authorities a server's certificate is checked against.
 *
 * The default, [systemDefault], is what an application wants unless it talks to a deployment with
 * its own authority. The variants are opaque on purpose, so more can be added without breaking a
 * `when` nobody should be writing over them.
 */
public sealed class TrustAnchors private constructor() {
    internal data object PlatformAnchors : TrustAnchors()

    internal class PinnedAnchors(
        private val pem: ByteArray,
    ) : TrustAnchors() {
        internal fun pem(): ByteArray = pem
    }

    internal data object NoVerification : TrustAnchors()

    public companion object {
        /**
         * The device's own certificate authorities, the same set the platform's HTTP clients use.
         *
         * The anchors are read from the platform on first use rather than when the client is built,
         * because reading them touches the disk, and then cached for the life of the process. An
         * authority installed while the process runs is therefore not picked up, which is also how
         * the platform treats a long-lived connection pool.
         *
         * Authorities the *user* installed are deliberately not included: an application targeting
         * API 24 or later does not trust those by default, and quietly widening that here would
         * make this client accept certificates every other client in the app rejects. Pass such a
         * certificate to [pinned] if a debugging proxy needs to be trusted.
         */
        @JvmStatic
        public fun systemDefault(): TrustAnchors = PlatformAnchors

        /**
         * Exactly the authorities in [pem], and nothing the platform trusts.
         *
         * This is how to reach a private deployment whose certificates are signed by an internal
         * authority. Pass one or more PEM `CERTIFICATE` blocks, concatenated.
         *
         * The bundle is parsed here so a malformed one is a mistake at this call. Without that it
         * would first be read when a connection is established, and surface as a connection
         * failure that names nothing about the bundle.
         *
         * @throws IllegalArgumentException if [pem] holds no certificate.
         */
        @JvmStatic
        public fun pinned(pem: ByteArray): TrustAnchors {
            val certificates =
                try {
                    CertificateFactory
                        .getInstance("X.509")
                        .generateCertificates(ByteArrayInputStream(pem))
                } catch (e: CertificateException) {
                    throw IllegalArgumentException(
                        "the trust anchors are not a readable PEM bundle: ${e.message}",
                        e,
                    )
                }
            require(certificates.isNotEmpty()) {
                "the trust anchors hold no certificate. Expected one or more PEM " +
                    "-----BEGIN CERTIFICATE----- blocks."
            }
            // Copied, and passed on unchanged rather than re-encoded: a caller's array is mutable,
            // and a bundle's order is the caller's business.
            return PinnedAnchors(pem.copyOf())
        }

        /**
         * Accepts any certificate, checking nothing. **Never ship this.**
         *
         * Every guarantee TLS provides is gone: the connection can be read and rewritten by anyone
         * on the path, and there is no longer anything tying the certificate to the origin, which
         * is also what made trying several candidate addresses for one origin safe.
         *
         * A client built with this logs an error on every construction, and says so louder when the
         * application is not debuggable. It is not blocked outright, so that a test against a
         * throwaway server stays possible, which means the only thing standing between this and
         * production is you.
         */
        @JvmStatic
        public fun insecureNoVerify(): TrustAnchors = NoVerification
    }
}

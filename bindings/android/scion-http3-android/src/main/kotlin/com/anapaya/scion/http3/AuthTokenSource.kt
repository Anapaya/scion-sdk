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

/**
 * The source that the client takes its tokens from, for
 * [ScionHttp3Client.Builder.authTokenSource].
 */
public sealed class AuthTokenSource private constructor() {
    internal class AnapayaAa(
        val apiKey: String,
        val aaUrl: String,
    ) : AuthTokenSource() {
        companion object {
            const val DEVICE_ID: String = "no-device-id"
        }
    }

    public companion object {
        /**
         * Exchanges an Anapaya AA API key for tokens, and renews the token.
         *
         * [aaUrl] has to be `https`, or `http` to a loopback host.
         */
        @JvmStatic
        public fun anapayaAa(
            apiKey: String,
            aaUrl: String,
        ): AuthTokenSource = AnapayaAa(apiKey, aaUrl)
    }
}

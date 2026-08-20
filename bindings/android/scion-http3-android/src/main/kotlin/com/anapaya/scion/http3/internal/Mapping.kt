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

import com.anapaya.scion.http3.PreferredUnderlay
import com.anapaya.scion.http3.ScionHttp3Exception
import com.anapaya.scion.http3.ScionHttp3Headers
import com.anapaya.scion.http3.ScionHttp3Request
import com.anapaya.scion.http3.ScionHttp3Response
import com.anapaya.scion.http3.ScionHttp3ResponseBody
import com.anapaya.scion.http3.SnapConfig
import com.anapaya.scion.http3.TrustAnchors
import com.anapaya.scion.http3.UdpConfig
import com.anapaya.scion.http3.uniffi.ClientConfig
import com.anapaya.scion.http3.uniffi.Header
import com.anapaya.scion.http3.uniffi.HttpRequest
import com.anapaya.scion.http3.uniffi.HttpResponse
import com.anapaya.scion.http3.uniffi.Underlay
import com.anapaya.scion.http3.uniffi.ScionHttp3Exception as FfiException
import com.anapaya.scion.http3.uniffi.SnapConfig as FfiSnapConfig
import com.anapaya.scion.http3.uniffi.TimeoutPhase as FfiTimeoutPhase
import com.anapaya.scion.http3.uniffi.TrustAnchors as FfiTrustAnchors
import com.anapaya.scion.http3.uniffi.UdpConfig as FfiUdpConfig

// The one place the public types and the generated ones meet.
//
// Confining it to a single file is what keeps the two `ScionHttp3Client` and `TrustAnchors` types,
// one public and one generated, from being a standing source of confusion: this is the only file
// that imports both, and it aliases the generated side.

/** The request as the stack receives it. */
internal fun ScionHttp3Request.toFfi(): HttpRequest =
    HttpRequest(
        url = url,
        method = method,
        headers = headers.map { Header(name = it.name, value = it.value) },
        // Absent and empty are different below: absent sends no body at all, where an empty one
        // sends a body of zero bytes. Preserve which the caller chose.
        body = body?.bytesNoCopy(),
        targets = targets.map { it.toString() },
        requestTimeoutMs = requestTimeoutMillis?.toULong(),
        maxResponseBodyBytes = maxResponseBodyBytes?.toULong(),
    )

/** The response as the application sees it. */
internal fun HttpResponse.toPublic(request: ScionHttp3Request): ScionHttp3Response =
    ScionHttp3Response(
        code = status.toInt(),
        headers = headers.toPublic(),
        body = ScionHttp3ResponseBody(body),
        // The stack reports no trailer section as an empty list, which cannot be told apart from an
        // empty section that was sent. Reported as absent, which is true far more often.
        trailers = if (trailers.isEmpty()) null else trailers.toPublic(),
        request = request,
    )

private fun List<Header>.toPublic(): ScionHttp3Headers =
    ScionHttp3Headers.ofEntries(
        map { ScionHttp3Headers.Entry(name = it.name, value = it.value) },
    )

/**
 * The public exception for a failure from the stack.
 *
 * `isRetryable` and `detail` are carried across untouched. Retryability is the stack's judgement,
 * which depends on what actually failed and not on which arm it lands in, so deriving it here would
 * be a second, worse answer to a question already answered.
 *
 * The `when` is exhaustive over a sealed type, so a new arm below is a compilation error here rather
 * than something that quietly becomes [ScionHttp3Exception.Internal].
 */
internal fun FfiException.toPublic(): ScionHttp3Exception =
    when (this) {
        is FfiException.StackBuild ->
            ScionHttp3Exception.Connectivity(retryable, detail, this)
        is FfiException.Resolution ->
            ScionHttp3Exception.Resolution(host, retryable, detail, this)
        is FfiException.Connect ->
            ScionHttp3Exception.Connect(host, port.toInt(), retryable, detail, this)
        is FfiException.Tls ->
            ScionHttp3Exception.Tls(host, retryable, detail, this)
        is FfiException.StreamReset ->
            ScionHttp3Exception.StreamReset(code.toLong(), retryable, detail, this)
        is FfiException.Protocol ->
            ScionHttp3Exception.Protocol(retryable, detail, this)
        is FfiException.ConnectionLimit ->
            ScionHttp3Exception.ConnectionLimit(retryable, detail, this)
        is FfiException.BodyTooLarge ->
            ScionHttp3Exception.BodyTooLarge(limit.toLong(), retryable, detail, this)
        is FfiException.Timeout ->
            ScionHttp3Exception.Timeout(
                phase.toPublic(),
                timeoutMs.toLong(),
                retryable,
                detail,
                this,
            )
        is FfiException.InvalidRequest ->
            ScionHttp3Exception.InvalidRequest(retryable, detail, this)
        is FfiException.Closed ->
            ScionHttp3Exception.Closed(retryable, detail, this)
        is FfiException.Internal ->
            ScionHttp3Exception.Internal(retryable, detail, this)
    }

private fun FfiTimeoutPhase.toPublic(): ScionHttp3Exception.TimeoutPhase =
    when (this) {
        FfiTimeoutPhase.CONNECT -> ScionHttp3Exception.TimeoutPhase.CONNECT
        FfiTimeoutPhase.REQUEST -> ScionHttp3Exception.TimeoutPhase.REQUEST
        FfiTimeoutPhase.BODY -> ScionHttp3Exception.TimeoutPhase.BODY
        FfiTimeoutPhase.OTHER -> ScionHttp3Exception.TimeoutPhase.OTHER
    }

/**
 * Applies the configured settings on top of the stack's own defaults.
 *
 * [base] is what `defaultClientConfig()` returned, so every field this leaves alone keeps the value
 * the SCION stack chose. That is the point: the defaults have exactly one home, and it is not here.
 */
internal fun ClientSettings.applyTo(
    base: ClientConfig,
    trust: FfiTrustAnchors,
): ClientConfig =
    base.copy(
        endhostApiUrl = endhostApiUrl,
        authToken = authToken ?: base.authToken,
        preferredUnderlay = preferredUnderlay?.toFfi() ?: base.preferredUnderlay,
        snap = snap?.toFfi() ?: base.snap,
        udp = udp?.toFfi() ?: base.udp,
        trust = trust,
        connectTimeoutMs = connectTimeoutMillis?.toULong() ?: base.connectTimeoutMs,
        requestTimeoutMs = requestTimeoutMillis?.toULong() ?: base.requestTimeoutMs,
        idleConnectionTimeoutMs =
            idleConnectionTimeoutMillis?.toULong() ?: base.idleConnectionTimeoutMs,
        maxOrigins = maxOrigins?.toUInt() ?: base.maxOrigins,
        connectionAttemptDelayMs =
            connectionAttemptDelayMillis?.toULong() ?: base.connectionAttemptDelayMs,
        maxResponseBodyBytes = maxResponseBodyBytes?.toULong() ?: base.maxResponseBodyBytes,
    )

private fun PreferredUnderlay.toFfi(): Underlay =
    when (this) {
        PreferredUnderlay.SNAP -> Underlay.SNAP
        PreferredUnderlay.UDP -> Underlay.UDP
    }

private fun SnapConfig.toFfi(): FfiSnapConfig =
    FfiSnapConfig(
        dpIndex = dataPlaneIndex?.toUInt(),
        staticIdentity = staticIdentity,
    )

private fun UdpConfig.toFfi(): FfiUdpConfig =
    FfiUdpConfig(
        outboundIps = outboundIps,
        nextHopResolverFetchIntervalMs = nextHopResolverFetchIntervalMillis?.toULong(),
    )

/**
 * The trust anchors the stack should use.
 *
 * The platform's anchors are read here and passed down as bytes, because the stack's TLS
 * implementation cannot read the keystore they live in. Its own "system default" would configure
 * nothing at all on Android, so it is never what this returns.
 */
internal fun TrustAnchors.toFfi(store: SystemTrustStore): FfiTrustAnchors =
    when (this) {
        is TrustAnchors.PlatformAnchors -> FfiTrustAnchors.Pem(store.anchorsPem())
        is TrustAnchors.PinnedAnchors -> FfiTrustAnchors.Pem(pem())
        is TrustAnchors.NoVerification -> FfiTrustAnchors.InsecureNoVerify
    }

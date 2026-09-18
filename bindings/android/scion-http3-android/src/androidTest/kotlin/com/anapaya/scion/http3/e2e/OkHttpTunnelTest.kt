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

package com.anapaya.scion.http3.e2e

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.anapaya.scion.http3.ScionHttp3Client
import com.anapaya.scion.http3.ScionTunnelSocketFactory
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetAddress
import java.net.UnknownHostException
import java.security.KeyStore
import java.security.cert.CertificateFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * E2e tests for OkHttp over [ScionTunnelSocketFactory] against the HTTP/1.1 servers the test
 * server runs inside a tunnel.
 */
@RunWith(AndroidJUnit4::class)
class OkHttpTunnelTest {
    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun okHttpFetchesThroughATunnel() {
        Fixture.clientFor(Fixture.HTTP1_HOST).use { client ->
            val okHttp = okHttpOver(client, Fixture.HTTP1_HOST).build()
            try {
                val url = "http://${Fixture.HTTP1_HOST}:${Fixture.port}/hello"
                okHttp.newCall(Request.Builder().url(url).build()).execute().use { response ->
                    assertEquals(200, response.code)
                    assertEquals(Protocol.HTTP_1_1, response.protocol)
                    assertEquals("world", response.body!!.string())
                }
            } finally {
                okHttp.connectionPool.evictAll()
            }
        }
    }

    /**
     * TLS runs on the platform's `SSLSocket` layered over the tunnel socket. The certificate is the
     * one the HTTP/3 server presents, so both layers verify against the same authority.
     */
    @Test(timeout = TEST_TIMEOUT_MILLIS)
    fun okHttpFetchesOverTlsInsideATunnel() {
        Fixture.clientFor(Fixture.TLS_HOST).use { client ->
            val trust = trustManagerFor(Fixture.info.caPem)
            val ssl = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trust), null) }
            val okHttp =
                okHttpOver(client, Fixture.TLS_HOST)
                    .sslSocketFactory(ssl.socketFactory, trust)
                    .build()
            try {
                val url = "https://${Fixture.TLS_HOST}:${Fixture.port}/hello"
                okHttp.newCall(Request.Builder().url(url).build()).execute().use { response ->
                    assertEquals(200, response.code)
                    assertEquals(Protocol.HTTP_1_1, response.protocol)
                    assertEquals("world", response.body!!.string())
                }
            } finally {
                okHttp.connectionPool.evictAll()
            }
        }
    }

    private fun okHttpOver(
        client: ScionHttp3Client,
        host: String,
    ): OkHttpClient.Builder =
        OkHttpClient
            .Builder()
            .socketFactory(ScionTunnelSocketFactory(client))
            .dns(
                object : Dns {
                    override fun lookup(hostname: String): List<InetAddress> {
                        if (hostname != host) throw UnknownHostException(hostname)
                        return listOf(InetAddress.getByAddress(hostname, byteArrayOf(0, 0, 0, 0)))
                    }
                },
            )

    private fun trustManagerFor(pem: String): X509TrustManager {
        val anchor =
            CertificateFactory
                .getInstance("X.509")
                .generateCertificate(pem.byteInputStream())
        val keyStore =
            KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null, null)
                setCertificateEntry("anchor", anchor)
            }
        val factory =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
                init(keyStore)
            }
        return factory.trustManagers.single() as X509TrustManager
    }
}

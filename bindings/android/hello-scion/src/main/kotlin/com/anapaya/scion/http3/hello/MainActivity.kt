// Copyright 2026 Anapaya Systems

package com.anapaya.scion.http3.hello

import android.app.Activity
import android.graphics.Typeface
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.anapaya.scion.http3.ScionHttp3Exception
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class MainActivity : Activity() {
    private val scope = CoroutineScope(Dispatchers.Main.immediate)

    /** Built on the first request, because it needs the test network's addressing to exist. */
    private var helloScion: HelloScion? = null

    private lateinit var output: TextView
    private lateinit var send: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(buildLayout())
        output.text = getString(R.string.press_send)
    }

    override fun onDestroy() {
        scope.cancel()
        helloScion?.close()
        helloScion = null
        super.onDestroy()
    }

    private fun onSendClicked() {
        send.isEnabled = false
        output.text = getString(R.string.sending)
        scope.launch {
            output.text = sendRequest()
            send.isEnabled = true
        }
    }

    private suspend fun sendRequest(): String =
        try {
            val reply = client().hello()
            "${reply.code}\n\n${reply.body}"
        } catch (e: ScionHttp3Exception) {
            describe(e)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // Reading the test network's configuration happens before any SCION call, so it fails
            // on its own terms. The screen is the only place a reader can see that.
            "${e::class.simpleName}: ${e.message ?: e}"
        }

    /** The client, built on first use and kept for the activity's life. */
    private suspend fun client(): HelloScion =
        helloScion ?: HelloScion(applicationContext, LocalNetwork.discover())
            .also { helloScion = it }

    // ANCHOR: errors

    /**
     * Every failure the client reports is a [ScionHttp3Exception]. A non-2xx status arrives as a
     * response instead, carrying a code and a body.
     */
    private fun describe(e: ScionHttp3Exception): String {
        val cause =
            when (e) {
                is ScionHttp3Exception.Connectivity -> "No usable network."
                is ScionHttp3Exception.Connect ->
                    "Could not reach ${e.host}:${e.port}. Is the test server still running?"
                is ScionHttp3Exception.Tls -> "The certificate ${e.host} presented was rejected."
                is ScionHttp3Exception.Timeout ->
                    "Gave up in the ${e.phase} phase after ${e.timeoutMillis} ms."
                else -> e.message ?: e.toString()
            }
        val advice = "Sending it again can succeed. The client does not retry on its own."
        return if (e.isRetryable) "$cause\n\n$advice" else cause
    }
    // ANCHOR_END: errors

    private fun buildLayout(): LinearLayout {
        val padding = (16 * resources.displayMetrics.density).toInt()

        send =
            Button(this).apply {
                text = getString(R.string.send_request)
                setOnClickListener { onSendClicked() }
            }

        output =
            TextView(this).apply {
                typeface = Typeface.MONOSPACE
                setTextIsSelectable(true)
            }

        val scroll =
            ScrollView(this).apply {
                addView(output, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
            }

        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.TOP
            setPadding(padding, padding, padding, padding)
            addView(send, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
            addView(scroll, LinearLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        }
    }
}

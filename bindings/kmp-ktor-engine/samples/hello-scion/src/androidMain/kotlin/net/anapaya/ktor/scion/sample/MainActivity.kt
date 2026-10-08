// Copyright 2026 Anapaya Systems

package net.anapaya.ktor.scion.sample

import android.app.Activity
import android.graphics.Typeface
import android.os.Bundle
import android.text.InputType
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import net.anapaya.ktor.scion.ScionTokenSource
import net.anapaya.ktor.scion.testing.ScionTestNetwork
import net.anapaya.ktor.scion.testing.useTestNetwork

/**
 * Runs [runSample] on a tap and shows its output.
 *
 * With an API key, the app authenticates with the AA, and it trusts the
 * device CAs through the platform verifier. An empty endhost API field
 * discovers the endhost APIs.
 *
 * Without an API key, the app sends the requests to the test API of a
 * [ScionTestNetwork] in the app process.
 */
class MainActivity : Activity() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val saved = getSharedPreferences("sample", MODE_PRIVATE)

        // Build the input fields with their saved values.
        fun field(key: String, hint: String, type: Int) = EditText(this).apply {
            this.hint = hint
            inputType = type
            isSingleLine = true
            setText(saved.getString(key, ""))
        }
        val uri = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
        val endhost = field(KEY_ENDHOST, "Endhost API URL (empty: discover)", uri)
        val token = field(
            KEY_API_KEY,
            "AA API key (empty: test network in the app)",
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD,
        )
        val url = field(KEY_URL, "Request URL", uri)

        // Run the sample on a tap.
        val output = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            setTextIsSelectable(true)
        }
        val run = Button(this).apply { text = "Run sample" }
        run.setOnClickListener {
            // Save the inputs.
            val endhostApiUrl = endhost.text.toString().trim()
            val apiKey = token.text.toString().trim()
            val requestUrl = url.text.toString().trim()
            saved.edit()
                .putString(KEY_ENDHOST, endhostApiUrl)
                .putString(KEY_API_KEY, apiKey)
                .putString(KEY_URL, requestUrl)
                .apply()

            // Run the sample and show its output.
            run.isEnabled = false
            output.text = ""
            scope.launch {
                val log = { line: String -> runOnUiThread { output.append(line + "\n") } }
                try {
                    if (apiKey.isEmpty()) {
                        val network = testNetwork
                        runSample("${network.testApiUrl}/hello", log) {
                            useTestNetwork(network)
                            caCertificatesPem = network.testApiCaPem
                        }
                    } else {
                        require(requestUrl.isNotEmpty()) { "enter a request URL" }
                        runSample(requestUrl, log) {
                            tokenSource = ScionTokenSource.AnapayaAa(apiKey = apiKey)
                            this.endhostApiUrl = endhostApiUrl.ifEmpty { null }
                        }
                    }
                } catch (e: Exception) {
                    log("failed: $e")
                } finally {
                    runOnUiThread { run.isEnabled = true }
                }
            }
        }

        // Lay out the views.
        val padding = (16 * resources.displayMetrics.density).toInt()
        setContentView(
            ScrollView(this).apply {
                // Android 15 draws apps edge to edge, under the status bar.
                fitsSystemWindows = true
                addView(
                    LinearLayout(this@MainActivity).apply {
                        orientation = LinearLayout.VERTICAL
                        setPadding(padding, padding, padding, padding)
                        addView(endhost)
                        addView(token)
                        addView(url)
                        addView(run)
                        addView(output)
                    },
                )
            },
        )
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}

/** Starts on the first run without an API key, and lives as long as the process. */
private val testNetwork: ScionTestNetwork by lazy { ScionTestNetwork.start() }

private const val KEY_ENDHOST = "endhost_api_url"
private const val KEY_API_KEY = "aa_api_key"
private const val KEY_URL = "request_url"

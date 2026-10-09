// Copyright 2026 Anapaya Systems

package net.anapaya.ktor.scion.sample

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import net.anapaya.ktor.scion.ScionTokenSource
import net.anapaya.ktor.scion.testing.ScionTestNetwork
import net.anapaya.ktor.scion.testing.useTestNetwork
import platform.Foundation.NSUserDefaults
import platform.UIKit.NSLayoutConstraint
import platform.UIKit.UIAction
import platform.UIKit.UIButton
import platform.UIKit.UIButtonTypeSystem
import platform.UIKit.UIColor
import platform.UIKit.UIControlEventTouchUpInside
import platform.UIKit.UIControlStateNormal
import platform.UIKit.UIFont
import platform.UIKit.UIFontWeightRegular
import platform.UIKit.UIKeyboardTypeURL
import platform.UIKit.UILayoutConstraintAxisVertical
import platform.UIKit.UIStackView
import platform.UIKit.UITextAutocapitalizationType
import platform.UIKit.UITextAutocorrectionType
import platform.UIKit.UITextBorderStyle
import platform.UIKit.UITextField
import platform.UIKit.UITextView
import platform.UIKit.UIViewController
import platform.UIKit.endEditing
import platform.UIKit.systemBackgroundColor
import platform.darwin.dispatch_async
import platform.darwin.dispatch_get_main_queue

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
@OptIn(ExperimentalForeignApi::class)
class SampleViewController : UIViewController(nibName = null, bundle = null) {
    // The screen lives as long as the app, so the scope never ends.
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val saved = NSUserDefaults.standardUserDefaults

    private val endhost = field(KEY_ENDHOST, "Endhost API URL (empty: discover)")
    private val token = field(KEY_API_KEY, "AA API key (empty: test network in the app)").apply {
        secureTextEntry = true
    }
    private val url = field(KEY_URL, "Request URL")
    private val run = UIButton.buttonWithType(UIButtonTypeSystem).apply {
        setTitle("Run sample", forState = UIControlStateNormal)
    }
    private val output = UITextView().apply {
        setEditable(false)
        font = UIFont.monospacedSystemFontOfSize(12.0, UIFontWeightRegular)
    }

    override fun viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor.systemBackgroundColor
        run.addAction(
            UIAction.actionWithHandler { onRun() },
            forControlEvents = UIControlEventTouchUpInside,
        )

        // Lay out the views, inside the safe area.
        val stack = UIStackView().apply {
            axis = UILayoutConstraintAxisVertical
            spacing = 12.0
            translatesAutoresizingMaskIntoConstraints = false
            listOf(endhost, token, url, run, output).forEach { addArrangedSubview(it) }
        }
        view.addSubview(stack)
        val area = view.safeAreaLayoutGuide
        NSLayoutConstraint.activateConstraints(
            listOf(
                stack.topAnchor.constraintEqualToAnchor(area.topAnchor, constant = 16.0),
                stack.bottomAnchor.constraintEqualToAnchor(area.bottomAnchor, constant = -16.0),
                stack.leadingAnchor.constraintEqualToAnchor(area.leadingAnchor, constant = 16.0),
                stack.trailingAnchor.constraintEqualToAnchor(area.trailingAnchor, constant = -16.0),
            ),
        )

        // With the launch argument -autorun YES, run as if the user tapped Run sample.
        // NSUserDefaults reads launch arguments of the form -key value.
        if (saved.boolForKey(KEY_AUTORUN)) {
            onRun()
        }
    }

    private fun onRun() {
        view.endEditing(true)

        // Save the inputs.
        val endhostApiUrl = endhost.text.orEmpty().trim()
        val apiKey = token.text.orEmpty().trim()
        val requestUrl = url.text.orEmpty().trim()
        saved.setObject(endhostApiUrl, forKey = KEY_ENDHOST)
        saved.setObject(apiKey, forKey = KEY_API_KEY)
        saved.setObject(requestUrl, forKey = KEY_URL)

        // Run the sample and show its output.
        run.enabled = false
        output.text = ""
        scope.launch {
            val log = { line: String ->
                onMain { output.text = output.text.orEmpty() + line + "\n" }
            }
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
                onMain { run.enabled = true }
            }
        }
    }

    /** Builds an input field with its saved value. */
    private fun field(key: String, placeholder: String) = UITextField().apply {
        this.placeholder = placeholder
        text = saved.stringForKey(key).orEmpty()
        borderStyle = UITextBorderStyle.UITextBorderStyleRoundedRect
        keyboardType = UIKeyboardTypeURL
        autocapitalizationType = UITextAutocapitalizationType.UITextAutocapitalizationTypeNone
        autocorrectionType = UITextAutocorrectionType.UITextAutocorrectionTypeNo
    }

    /** UIKit takes changes only on the main thread. The queue keeps the order of the lines. */
    private fun onMain(block: () -> Unit) = dispatch_async(dispatch_get_main_queue(), block)
}

/** Starts on the first run without an API key, and lives as long as the process. */
private val testNetwork: ScionTestNetwork by lazy { ScionTestNetwork.start() }

private const val KEY_ENDHOST = "endhost_api_url"
private const val KEY_API_KEY = "aa_api_key"
private const val KEY_URL = "request_url"
private const val KEY_AUTORUN = "autorun"

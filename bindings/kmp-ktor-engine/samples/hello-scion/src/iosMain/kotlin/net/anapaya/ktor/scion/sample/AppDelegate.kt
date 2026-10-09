// Copyright 2026 Anapaya Systems

package net.anapaya.ktor.scion.sample

import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.ObjCObjectBase
import kotlinx.cinterop.autoreleasepool
import platform.Foundation.NSStringFromClass
import platform.UIKit.UIApplication
import platform.UIKit.UIApplicationDelegateProtocol
import platform.UIKit.UIApplicationDelegateProtocolMeta
import platform.UIKit.UIApplicationMain
import platform.UIKit.UIResponder
import platform.UIKit.UIResponderMeta
import platform.UIKit.UIScreen
import platform.UIKit.UIWindow

/**
 * The entry point of the iOS app. It starts UIKit with [AppDelegate].
 *
 * The name is not `main`, because `main` in commonMain is the command line
 * sample.
 */
@OptIn(BetaInteropApi::class, ExperimentalForeignApi::class)
fun startIosApp() {
    autoreleasepool {
        UIApplicationMain(0, null, null, NSStringFromClass(AppDelegate))
    }
}

/** Shows [SampleViewController] in the one window of the app. */
@OptIn(BetaInteropApi::class, ExperimentalForeignApi::class)
class AppDelegate @ObjCObjectBase.OverrideInit constructor() :
    UIResponder(),
    UIApplicationDelegateProtocol {
    companion object : UIResponderMeta(), UIApplicationDelegateProtocolMeta

    // UIKit keeps no reference to a window that the app creates.
    private var mainWindow: UIWindow? = null

    override fun application(
        application: UIApplication,
        didFinishLaunchingWithOptions: Map<Any?, *>?,
    ): Boolean {
        mainWindow = UIWindow(frame = UIScreen.mainScreen.bounds).apply {
            rootViewController = SampleViewController()
            makeKeyAndVisible()
        }
        return true
    }
}

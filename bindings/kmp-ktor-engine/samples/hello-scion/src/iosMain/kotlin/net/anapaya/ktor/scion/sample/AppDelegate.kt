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
import platform.UIKit.UIScene
import platform.UIKit.UISceneConfiguration
import platform.UIKit.UISceneConnectionOptions
import platform.UIKit.UISceneSession
import platform.UIKit.UIWindow
import platform.UIKit.UIWindowScene
import platform.UIKit.UIWindowSceneDelegateProtocol
import platform.UIKit.UIWindowSceneDelegateProtocolMeta

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

/** Gives each scene of the app a [SceneDelegate]. */
@OptIn(BetaInteropApi::class, ExperimentalForeignApi::class)
class AppDelegate @ObjCObjectBase.OverrideInit constructor() :
    UIResponder(),
    UIApplicationDelegateProtocol {
    companion object : UIResponderMeta(), UIApplicationDelegateProtocolMeta

    override fun application(
        application: UIApplication,
        configurationForConnectingSceneSession: UISceneSession,
        options: UISceneConnectionOptions,
    ): UISceneConfiguration = UISceneConfiguration(
        name = null,
        sessionRole = configurationForConnectingSceneSession.role,
    ).apply {
        delegateClass = SceneDelegate
    }
}

/** Shows [SampleViewController] in the window of the scene. */
@OptIn(BetaInteropApi::class, ExperimentalForeignApi::class)
class SceneDelegate @ObjCObjectBase.OverrideInit constructor() :
    UIResponder(),
    UIWindowSceneDelegateProtocol {
    companion object : UIResponderMeta(), UIWindowSceneDelegateProtocolMeta

    private var mainWindow: UIWindow? = null

    override fun scene(
        scene: UIScene,
        willConnectToSession: UISceneSession,
        options: UISceneConnectionOptions,
    ) {
        mainWindow = UIWindow(windowScene = scene as UIWindowScene).apply {
            rootViewController = SampleViewController()
            makeKeyAndVisible()
        }
    }
}

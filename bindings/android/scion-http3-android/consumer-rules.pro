# Copyright 2026 Anapaya Systems

# ProGuard rules for consumers of this library.
#
# R8, the optimiser and shrinker that Android release builds run, removes and renames code it cannot
# see a reference to. Calls made from native code into Kotlin are invisible to it, thus, the types
# and methods the native library looks up by name need `-keep`
# rules here. Rules in this file are merged into every consuming application's configuration, which
# is why they belong with the library rather than with each application.
#
# See https://developer.android.com/topic/performance/app-optimization/enable-app-optimization.

# JNA's own runtime, including the Structure and Callback subclasses it instantiates reflectively.
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { public *; }

# The generated bindings: their Structure subclasses carry the FFI layouts, and their callback
# implementations are invoked from Rust.
-keep class com.anapaya.scion.http3.uniffi.** { *; }

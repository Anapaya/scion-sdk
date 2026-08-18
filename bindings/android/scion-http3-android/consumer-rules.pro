# Copyright 2026 Anapaya Systems

# ProGuard rules for consumers of this library. Empty for now.
#
# R8, the optimiser and shrinker that Android release builds run, removes and renames code it cannot
# see a reference to. Calls made from native code into Kotlin are invisible to it, so once the
# generated bindings land, the types and methods the native library looks up by name need `-keep`
# rules here. Rules in this file are merged into every consuming application's configuration, which
# is why they belong with the library rather than with each application.
#
# See https://developer.android.com/topic/performance/app-optimization/enable-app-optimization.

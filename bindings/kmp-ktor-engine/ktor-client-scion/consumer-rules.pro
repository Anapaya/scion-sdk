# The Rust library calls these classes over JNI. R8 cannot see that use.
-keep, includedescriptorclasses class org.rustls.platformverifier.** { *; }
-keepclasseswithmembernames class net.anapaya.ktor.scion.AndroidTrust { native <methods>; }

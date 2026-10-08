# Copyright 2026 Anapaya Systems

# cargo sets TARGET and CARGO_CFG_TARGET_ARCH for the build script, and CMake
# inherits them. Gobley sets ANDROID_NDK_HOME and CC_<triple>.

# The ABI of the Rust target.
set(_arch "$ENV{CARGO_CFG_TARGET_ARCH}")
if(_arch STREQUAL "aarch64")
  set(ANDROID_ABI arm64-v8a)
elseif(_arch STREQUAL "arm")
  set(ANDROID_ABI armeabi-v7a)
elseif(_arch STREQUAL "x86")
  set(ANDROID_ABI x86)
elseif(_arch STREQUAL "x86_64")
  set(ANDROID_ABI x86_64)
else()
  message(FATAL_ERROR "No Android ABI for the Rust architecture '${_arch}'")
endif()

# The API level. Gobley puts the minSdk of the module into the name of the
# NDK compiler, for example aarch64-linux-android21-clang.
set(_cc "$ENV{CC_$ENV{TARGET}}")
if(NOT _cc MATCHES "([0-9]+)-clang(\\.cmd)?$")
  message(FATAL_ERROR "No API level in CC_$ENV{TARGET}='${_cc}'")
endif()
set(ANDROID_PLATFORM "${CMAKE_MATCH_1}")

set(ANDROID_STL c++_shared)
include("$ENV{ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake")

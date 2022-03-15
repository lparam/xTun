#!/bin/sh
export TARGET_ARCH=armv8-a
export CFLAGS="-Os -march=${TARGET_ARCH}"
export TOOLCHAIN=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64
export CC=$TOOLCHAIN/bin/aarch64-linux-android29-clang
export CXX=$TOOLCHAIN/bin/aarch64-linux-android29-clang++
NDK_PLATFORM=android-29 ARCH=arm64 HOST_COMPILER=aarch64-linux-android "$(dirname "$0")/android-build.sh"
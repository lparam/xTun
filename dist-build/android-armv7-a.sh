#!/bin/sh
export TARGET_ARCH=armv7-a
export CFLAGS="-Os -mfloat-abi=softfp -mfpu=vfpv3-d16 -mthumb -marm -march=${TARGET_ARCH} -fPIC"
export TOOLCHAIN=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64
export CC=$TOOLCHAIN/bin/armv7a-linux-androideabi29-clang
export CXX=$TOOLCHAIN/bin/armv7a-linux-androideabi29-clang++
ARCH=armv7-a HOST_COMPILER=armv7a-linux-androideabi "$(dirname "$0")/android-build.sh"
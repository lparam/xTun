#!/bin/sh
export TARGET_ARCH=armv7-a
export CFLAGS="-Os -mfloat-abi=softfp -mfpu=vfpv3-d16 -mthumb -marm -march=${TARGET_ARCH} -fPIC"
ARCH=armv7-a HOST_COMPILER=arm-linux-androideabi CC=armv7a-linux-androideabi21-clang "$(dirname "$0")/android-build.sh"
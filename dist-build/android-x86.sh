#!/bin/sh
export TARGET_ARCH=i686
export CFLAGS="-Os -march=${TARGET_ARCH} -fPIC"
ARCH=x86 HOST_COMPILER=i686-linux-android CC=i686-linux-android21-clang "$(dirname "$0")/android-build.sh"

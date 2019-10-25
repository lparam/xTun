#! /bin/sh

if [ -z "$ANDROID_NDK_HOME" ]; then
    echo "You should probably set ANDROID_NDK_HOME to the directory containing"
    echo "the Android NDK"
    exit
fi

if [ "x$TARGET_ARCH" = 'x' ] || [ "x$ARCH" = 'x' ] || [ "x$HOST_COMPILER" = 'x' ]; then
    echo "You shouldn't use android-build.sh directly, use android-[arch].sh instead"
    exit 1
fi

export TOOLCHAIN=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64
export PREFIX="$(pwd)/xTun-android-${TARGET_ARCH}"
export PATH="${PATH}:${TOOLCHAIN}/bin"

make CROSS="${HOST_COMPILER}-" CC="${CC}" O="${PREFIX}" android V=1
echo "xTun has been installed into $PREFIX"
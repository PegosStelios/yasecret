#!/bin/bash
set -e
cd "${SRCROOT}/.."

# Outside Xcode's environment (see macos/Scripts/build_rust.sh).
cargo() {
    env -i HOME="$HOME" USER="$USER" TMPDIR="$TMPDIR" IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-17.0}" \
        PATH="$HOME/.cargo/bin:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin" \
        cargo "$@"
}

case "${PLATFORM_NAME}" in
    iphonesimulator) TARGET=aarch64-apple-ios-sim ;;
    *) TARGET=aarch64-apple-ios ;;
esac
if [ "${CONFIGURATION}" = "Release" ]; then FLAGS=--release; PROFILE=release; else FLAGS=; PROFILE=debug; fi

cargo build $FLAGS --target "$TARGET" -p yasecret-ffi
cargo run $FLAGS -p uniffi-bindgen -- generate \
    --library "target/$TARGET/$PROFILE/libyasecret_ffi.dylib" \
    --language swift \
    --out-dir "${SRCROOT}/Generated/"

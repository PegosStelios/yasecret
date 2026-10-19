#!/bin/bash
set -e
WORKSPACE="${SRCROOT}/.."
cd "${WORKSPACE}"
if [ "${CONFIGURATION}" = "Release" ]; then
    PROFILE=release
    FLAGS=--release
else
    PROFILE=debug
    FLAGS=
fi
# Run cargo outside Xcode's build environment: its SDK/linker variables leak into host
# builds and can produce proc-macro dylibs that dyld refuses to load.
cargo() {
    env -i HOME="$HOME" USER="$USER" TMPDIR="$TMPDIR" \
        PATH="$HOME/.cargo/bin:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin" \
        cargo "$@"
}
cargo build $FLAGS -p yasecret-ffi
# Same profile for the bindgen so Release doesn't compile a second, debug dependency tree.
cargo run $FLAGS -p uniffi-bindgen -- generate \
    --library "target/${PROFILE}/libyasecret_ffi.dylib" \
    --language swift \
    --out-dir "${SRCROOT}/Generated/"

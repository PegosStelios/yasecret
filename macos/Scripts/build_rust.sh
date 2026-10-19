#!/bin/bash
set -e
WORKSPACE="${SRCROOT}/.."
cd "${WORKSPACE}"
if [ "${CONFIGURATION}" = "Release" ]; then
    cargo build --release -p yasecret-ffi
    PROFILE=release
else
    cargo build -p yasecret-ffi
    PROFILE=debug
fi
cargo run -p uniffi-bindgen -- generate \
    --library "target/${PROFILE}/libyasecret_ffi.dylib" \
    --language swift \
    --out-dir "${SRCROOT}/Generated/"

#!/bin/bash
set -e
WORKSPACE="${SRCROOT}/.."
cd "${WORKSPACE}"
cargo build -p yasecret-ffi
cargo run -p uniffi-bindgen -- generate \
    --library target/debug/libyasecret_ffi.dylib \
    --language swift \
    --out-dir "${SRCROOT}/Generated/"

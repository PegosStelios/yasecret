#!/bin/bash
set -e
WORKSPACE="${SRCROOT}/.."
cd "${WORKSPACE}"

# Run cargo outside Xcode's build environment: its SDK/linker variables leak into host
# builds and can produce proc-macro dylibs that dyld refuses to load.
cargo() {
    env -i HOME="$HOME" USER="$USER" TMPDIR="$TMPDIR" \
        PATH="$HOME/.cargo/bin:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin" \
        cargo "$@"
}

if [ "${CONFIGURATION}" = "Release" ]; then
    # One static library containing every architecture Xcode is building.
    libs=()
    for arch in ${ARCHS:-arm64}; do
        case "$arch" in
            arm64) target=aarch64-apple-darwin ;;
            x86_64) target=x86_64-apple-darwin ;;
            *) echo "error: unsupported architecture $arch" >&2; exit 1 ;;
        esac
        cargo build --release --target "$target" -p yasecret-ffi
        libs+=("target/$target/release/libyasecret_ffi.a")
        BINDGEN_LIB="target/$target/release/libyasecret_ffi.dylib"
    done
    mkdir -p target/universal/release
    lipo -create "${libs[@]}" -output target/universal/release/libyasecret_ffi.a
    FLAGS=--release
else
    cargo build -p yasecret-ffi
    BINDGEN_LIB=target/debug/libyasecret_ffi.dylib
    FLAGS=
fi
# Same profile for the bindgen so Release doesn't compile a second, debug dependency tree.
cargo run $FLAGS -p uniffi-bindgen -- generate \
    --library "$BINDGEN_LIB" \
    --language swift \
    --out-dir "${SRCROOT}/Generated/"

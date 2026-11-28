#!/usr/bin/env sh
# Build the browser WASM bindings into packages/ts-bindings/src/wasm-gen
# (gitignored). Requires the wasm32 target and wasm-pack.
#
#   sh scripts/build-wasm.sh
set -e

cd "$(dirname "$0")/.."

if ! command -v wasm-pack >/dev/null 2>&1; then
    echo "wasm-pack not found; install it: https://rustwasm.github.io/wasm-pack/" >&2
    exit 1
fi

rustup target add wasm32-unknown-unknown

# One entry point for the wasm build chain (dispatch SYNCBOND-WEB-001):
# wasm-pack -> packages/ts-bindings/src/wasm-gen, which the TypeScript
# bindings and the web demo both import. Kept in sync with the equivalent
# script in packages/ts-bindings/package.json (build:wasm).
wasm-pack build crates/syncbond-wasm \
    --target web \
    --release \
    --out-dir "$PWD/packages/ts-bindings/src/wasm-gen"

echo "wasm bindings built into packages/ts-bindings/src/wasm-gen"

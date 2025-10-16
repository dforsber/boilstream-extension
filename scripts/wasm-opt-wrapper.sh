#!/bin/bash
# Wrapper for wasm-opt that filters out deprecated --enable-bulk-memory-opt flag
# This allows building with Emscripten 3.1.71 which removed this flag

# Find the real wasm-opt (not this wrapper)
REAL_WASM_OPT=""
for path in $(echo "$PATH" | tr ':' '\n'); do
    if [ -x "$path/wasm-opt" ] && [ "$path/wasm-opt" != "$0" ]; then
        # Skip if this is our wrapper
        if [ "$(basename "$path")" != "scripts" ]; then
            REAL_WASM_OPT="$path/wasm-opt"
            break
        fi
    fi
done

if [ -z "$REAL_WASM_OPT" ]; then
    echo "Error: Could not find real wasm-opt in PATH" >&2
    exit 1
fi

# Filter out the deprecated flag
FILTERED_ARGS=()
for arg in "$@"; do
    if [ "$arg" != "--enable-bulk-memory-opt" ]; then
        FILTERED_ARGS+=("$arg")
    fi
done

# Execute the real wasm-opt with filtered arguments
exec "$REAL_WASM_OPT" "${FILTERED_ARGS[@]}"

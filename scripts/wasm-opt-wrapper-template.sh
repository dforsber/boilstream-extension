#!/bin/bash
# Wrapper to filter out unsupported flags (removed in Emscripten 3.1.50+)
# This wrapper is automatically installed by CMakeLists.txt during WASM builds

# List of flags to filter out (removed in newer wasm-opt versions)
FILTERED_FLAGS=(
    "--enable-bulk-memory-opt"
    "--enable-call-indirect-overlong"
)

args=()
for arg in "$@"; do
    # Check if this arg should be filtered
    skip=false
    for filtered in "${FILTERED_FLAGS[@]}"; do
        if [ "$arg" = "$filtered" ]; then
            skip=true
            break
        fi
    done

    # Add to args if not filtered
    if [ "$skip" = false ]; then
        args+=("$arg")
    fi
done

# Execute the real wasm-opt with filtered arguments
exec "WASM_OPT_REAL_PATH" "${args[@]}"

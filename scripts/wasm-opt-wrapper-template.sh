#!/bin/bash
# Wrapper to completely skip wasm-opt optimization
# wasm-opt aggressively strips Rust static library symbols even with filtered flags
# This wrapper bypasses wasm-opt entirely by copying input to output

# Handle --version check (CMake and build tools check this)
if [ "$1" = "--version" ] || [ "$1" = "-version" ]; then
    echo "wasm-opt version 124 (wrapper - optimization disabled)"
    exit 0
fi

# Parse arguments to find input and output files
# wasm-opt is called like: wasm-opt [options] input.wasm -o output.wasm
output_file=""
input_file=""
next_is_output=0

for arg in "$@"; do
    if [ "$arg" = "-o" ]; then
        next_is_output=1
    elif [ $next_is_output -eq 1 ]; then
        output_file="$arg"
        next_is_output=0
    elif [ -f "$arg" ] && [ -z "$input_file" ]; then
        input_file="$arg"
    fi
done

# If we have both input and output, copy without optimization
if [ -n "$input_file" ] && [ -n "$output_file" ]; then
    cp "$input_file" "$output_file"
    exit 0
fi

# For any other call (like checks), just succeed
exit 0

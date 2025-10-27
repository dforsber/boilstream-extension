#!/bin/bash

# Compile and run WASM FFI test for opaque-client
#
# This script compiles a simple C test program that links against the
# Rust opaque-client library compiled to WASM, and tests the FFI interface.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  OPAQUE Client WASM FFI Build & Test                      ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}\n"

# Check if emcc is available
if ! command -v emcc &> /dev/null; then
    echo -e "${RED}✗ emcc not found!${NC}"
    echo -e "${YELLOW}  Please install Emscripten: https://emscripten.org/docs/getting_started/downloads.html${NC}"
    echo -e "${YELLOW}  Or activate it: source \$EMSDK/emsdk_env.sh${NC}"
    exit 1
fi

echo -e "${GREEN}✓ emcc found: $(emcc --version | head -1)${NC}\n"

# Check if Rust library exists
RUST_LIB="../target/wasm32-unknown-emscripten/release/libopaque_client.a"

if [ ! -f "$RUST_LIB" ]; then
    echo -e "${YELLOW}⚠ Rust WASM library not found at: $RUST_LIB${NC}"
    echo -e "${YELLOW}  Building it now...${NC}\n"

    cd ..
    cargo build --target wasm32-unknown-emscripten --release
    cd test-wasm

    if [ ! -f "$RUST_LIB" ]; then
        echo -e "${RED}✗ Failed to build Rust WASM library${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}✓ Rust WASM library found${NC}"
RUST_LIB_SIZE=$(du -h "$RUST_LIB" | cut -f1)
echo -e "${BLUE}  Size: $RUST_LIB_SIZE${NC}\n"

# Compile the C test program
echo -e "${BLUE}Compiling C test program with emcc...${NC}"

# Basic compilation (produces test-ffi.js and test-ffi.wasm)
emcc test-ffi.c "$RUST_LIB" \
    -o test-ffi.js \
    -s EXPORTED_FUNCTIONS='["_main","_malloc","_free"]' \
    -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap"]' \
    -s ALLOW_MEMORY_GROWTH=1 \
    -s TOTAL_MEMORY=33554432 \
    -s EXIT_RUNTIME=1 \
    --no-entry

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Compilation successful!${NC}\n"
else
    echo -e "${RED}✗ Compilation failed${NC}"
    exit 1
fi

# Check output files
if [ -f "test-ffi.js" ] && [ -f "test-ffi.wasm" ]; then
    WASM_SIZE=$(du -h test-ffi.wasm | cut -f1)
    echo -e "${GREEN}✓ Output files created:${NC}"
    echo -e "${BLUE}  test-ffi.js${NC}"
    echo -e "${BLUE}  test-ffi.wasm (${WASM_SIZE})${NC}\n"
else
    echo -e "${RED}✗ Output files not found${NC}"
    exit 1
fi

# Run the test
echo -e "${BLUE}Running WASM FFI tests...${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}\n"

node test-ffi.js

TEST_RESULT=$?

echo -e "\n${BLUE}═══════════════════════════════════════════════════════════${NC}\n"

if [ $TEST_RESULT -eq 0 ]; then
    echo -e "${GREEN}✓ All FFI tests passed!${NC}"
    echo -e "${GREEN}✓ WASM build is working correctly${NC}\n"
    exit 0
else
    echo -e "${RED}✗ Some FFI tests failed${NC}"
    echo -e "${YELLOW}  Please check the output above for details${NC}\n"
    exit 1
fi

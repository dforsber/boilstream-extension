#!/bin/bash

# Build WASM integration test using actual opaque-client library
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Building WASM Integration Test                           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}\n"

# Check emcc
if ! command -v emcc &> /dev/null; then
    echo -e "${RED}✗ emcc not found!${NC}"
    echo -e "${YELLOW}  Install Emscripten or activate: source \$EMSDK/emsdk_env.sh${NC}"
    exit 1
fi

echo -e "${GREEN}✓ emcc found: $(emcc --version | head -1)${NC}\n"

# Build Rust library if needed
RUST_LIB="../target/wasm32-unknown-emscripten/release/libopaque_client.a"
if [ ! -f "$RUST_LIB" ]; then
    echo -e "${YELLOW}Building Rust library...${NC}"
    cd ..
    cargo build --target wasm32-unknown-emscripten --release
    cd test-wasm
fi

echo -e "${GREEN}✓ Rust library ready${NC}"
echo -e "${BLUE}  Size: $(du -h "$RUST_LIB" | cut -f1)${NC}\n"

# Compile integration test
echo -e "${BLUE}Compiling integration test...${NC}"

emcc integration-test.c "$RUST_LIB" \
    -o integration-test.js \
    -s EXPORTED_FUNCTIONS='["_main","_malloc","_free"]' \
    -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap","UTF8ToString","stringToUTF8","HEAP32","HEAPU8"]' \
    -s ALLOW_MEMORY_GROWTH=1 \
    -s INITIAL_MEMORY=67108864 \
    -s MODULARIZE=1 \
    -s EXPORT_NAME='createModule' \
    -s ENVIRONMENT=node

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Compilation successful!${NC}\n"
else
    echo -e "${RED}✗ Compilation failed${NC}"
    exit 1
fi

# Check outputs
if [ -f "integration-test.js" ] && [ -f "integration-test.wasm" ]; then
    WASM_SIZE=$(du -h integration-test.wasm | cut -f1)
    echo -e "${GREEN}✓ Output files created:${NC}"
    echo -e "${BLUE}  integration-test.js${NC}"
    echo -e "${BLUE}  integration-test.wasm (${WASM_SIZE})${NC}\n"
else
    echo -e "${RED}✗ Output files not found${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Build complete!${NC}\n"
echo -e "${BLUE}Run tests:${NC}"
echo -e "${YELLOW}  # Local tests only:${NC}"
echo -e "  node integration-test.js\n"
echo -e "${YELLOW}  # With server:${NC}"
echo -e "  node integration-test.js --server=https://localhost:4332 --token=YOUR_BOOTSTRAP_TOKEN\n"

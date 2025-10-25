#!/bin/bash

# Build simple WASM test (no Emscripten Fetch API)
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Building Simple WASM Test                                ║${NC}"
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

# Compile simple test
echo -e "${BLUE}Compiling simple test...${NC}"

emcc integration-simple.c "$RUST_LIB" \
    -o integration-simple.js \
    -s EXPORTED_FUNCTIONS='["_main","_malloc","_free","_opaque_client_registration_start","_opaque_client_registration_finish","_opaque_client_login_start","_opaque_client_login_finish","_opaque_free_buffer","_opaque_free_registration_state","_opaque_free_login_state","_opaque_registration_start_wrapper","_opaque_login_start_wrapper","_opaque_free_buffer_data"]' \
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
if [ -f "integration-simple.js" ] && [ -f "integration-simple.wasm" ]; then
    WASM_SIZE=$(du -h integration-simple.wasm | cut -f1)
    echo -e "${GREEN}✓ Output files created:${NC}"
    echo -e "${BLUE}  integration-simple.js${NC}"
    echo -e "${BLUE}  integration-simple.wasm (${WASM_SIZE})${NC}\n"
else
    echo -e "${RED}✗ Output files not found${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Build complete!${NC}\n"
echo -e "${BLUE}Run tests:${NC}"
echo -e "${YELLOW}  # Local tests:${NC}"
echo -e "  node integration-simple.js\n"
echo -e "${YELLOW}  # With server (uses Node.js wrapper):${NC}"
echo -e "  node integration-server.cjs --server=https://localhost:4332 --token=YOUR_TOKEN\n"

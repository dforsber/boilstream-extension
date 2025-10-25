# OPAQUE Client WASM Test Suite

This directory contains standalone tests to verify that the `opaque-client` Rust library correctly compiles to WebAssembly and functions properly.

## Overview

The `opaque-client` library is compiled to `wasm32-unknown-emscripten` target, which produces a static library (`.a` file) that can be linked with C/C++ code compiled by Emscripten. This is the approach used by the DuckDB extension.

## Test Structure

### 1. Basic WASM Build Verification (`test-opaque.js`)

Verifies that:
- The Rust code compiles to WASM target successfully
- The static library file is generated correctly
- The library has the correct format (ar archive)
- Expected C FFI symbols are available for linking

**Run:**
```bash
npm run test
```

### 2. DuckDB Extension WASM Build Test

To fully test the WASM functionality, we need to build and test the complete DuckDB extension:

**Build for WASM:**
```bash
cd ../..  # Back to extension root
make wasm
```

This will:
1. Compile the Rust opaque-client to WASM
2. Compile the C++ extension code to WASM
3. Link everything together with DuckDB WASM
4. Produce a `.wasm` extension file

### 3. Integration Test with Boilstream Server

For a complete end-to-end test, you can test the WASM build against your boilstream server.

## Understanding wasm32-unknown-emscripten

The `wasm32-unknown-emscripten` target:
- Uses Emscripten's toolchain
- Provides POSIX-compatible libc (musl)
- Supports interop with C/C++ code
- Produces static libraries (.a) for linking
- Is ideal for projects that need to integrate Rust with C/C++

This is different from `wasm32-unknown-unknown`, which:
- Produces pure WASM modules
- Has limited std support
- Is typically used with wasm-bindgen for direct JavaScript interop
- Cannot easily interop with C/C++ code

## Test Levels

### Level 1: Rust Compilation ✅
**Status:** PASSED
- `cargo build --target wasm32-unknown-emscripten --release` succeeds
- Static library `libopaque_client.a` is generated
- File size: ~3.3 MB

### Level 2: C++ Linking
**How to test:**
```bash
cd ../..
mkdir -p build/wasm_eh
cd build/wasm_eh
emcmake cmake -DCMAKE_BUILD_TYPE=Release ../..
emmake make
```

This tests that:
- The Rust static library links correctly with C++ code
- The C FFI interface works
- All symbols resolve properly

### Level 3: DuckDB Extension Loading
**How to test:**
```bash
cd ../../test/wasm
npm install
npm test
```

This tests that:
- The WASM extension loads in DuckDB WASM
- SQL functions are registered correctly
- OPAQUE protocol functions execute properly

### Level 4: Integration with Boilstream Server
**How to test:**
Run your actual integration tests that connect to the boilstream server.

## Current Status

✅ **Level 1 PASSED**: Rust compiles to WASM successfully
⏳ **Level 2**: Ready to test C++ linking
⏳ **Level 3**: Ready to test DuckDB extension
⏳ **Level 4**: Ready for integration tests

## Quick Start

1. **Build WASM library:**
   ```bash
   npm run build
   ```

2. **Verify build:**
   ```bash
   npm test
   ```

3. **Test C FFI (requires Emscripten):**
   ```bash
   npm run test:ffi
   ```

   This compiles a C test program that links the WASM library and tests the FFI interface directly.
   **Requirements:** Emscripten SDK must be installed and activated.

4. **Build full extension:**
   ```bash
   cd ../..
   make wasm
   ```

## Debugging

If you encounter issues:

1. **Check Rust target is installed:**
   ```bash
   rustup target list | grep wasm32-unknown-emscripten
   ```
   If not installed: `rustup target add wasm32-unknown-emscripten`

2. **Check Emscripten is available:**
   ```bash
   emcc --version
   ```

3. **Verify the static library:**
   ```bash
   file target/wasm32-unknown-emscripten/release/libopaque_client.a
   ```
   Should output: "current ar archive"

4. **Check for symbols (on macOS):**
   ```bash
   nm target/wasm32-unknown-emscripten/release/libopaque_client.a | grep opaque_client
   ```

## Next Steps

To create a truly standalone WASM test that doesn't require DuckDB:

1. Modify `Cargo.toml` to add a `cdylib` crate type for WASM target
2. Create Emscripten HTML/JS wrapper
3. Load the module in Node.js or browser
4. Call FFI functions directly from JavaScript

However, for your use case (DuckDB extension), the current approach is correct and optimal.

# DuckDB WASM Extension Test - Current Status

**Date:** 2025-10-26
**Status:** ⚠️ Extension loading fails with symbol mismatch

## Test Infrastructure ✅

Successfully created and configured:

1. ✅ **Browser-based test**: `test-wasm-browser.html`
2. ✅ **HTTP server**: `server.js` (serves on port 8080)
3. ✅ **DuckDB WASM loading**: Using latest version from CDN
4. ✅ **Configuration**: `allowUnsignedExtensions: true` properly set
5. ✅ **Format detection**: Automatically matches wasm_eh/wasm_mvp/wasm_threads

## What Works ✅

- DuckDB WASM loads successfully from CDN (latest version)
- Worker creation with blob URL (avoids CORS)
- Database instantiation with proper configuration
- Connection and basic queries work (`SELECT 42`)
- Extension file fetching from localhost server
- `INSTALL` command succeeds
- Version and format matching (v1.4.1, wasm_eh)

## Current Issue ❌

### Error
```
IO Error: Extension could not be loaded: Could not load dynamic lib: boilstream
LinkError: WebAssembly.Instance(): Import #5 "env"
"_ZN6duckdb17InternalExceptionC2IJyyEEERKNSt3__212basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEEDpT_":
imported function does not match the expected type
```

### Analysis

This is a **symbol/ABI mismatch error**:

1. **Symbol Name**: `_ZN6duckdb17InternalExceptionC2IJyyEEE...`
   - This is a mangled C++ symbol for `duckdb::InternalException` constructor
   - The template parameters suggest it's being instantiated with `<unsigned long long, unsigned long long>`

2. **Root Cause**: The extension expects a different function signature than what DuckDB WASM provides

### Possible Causes

1. **Compiler Mismatch**:
   - Extension built with different compiler version/flags than DuckDB WASM
   - Different C++ standard library (libc++ vs libstdc++)

2. **DuckDB Version Mismatch**:
   - Even though both claim v1.4.1, there might be API differences
   - Browser WASM build might have different ABI than the extension was built against

3. **Build Configuration**:
   - Different Emscripten flags used
   - Different optimization levels
   - Different exception handling settings (wasm_eh vs wasm_mvp)

## Build Details

### Extension Build
- Path: `build/wasm_eh/repository/v1.4.1/wasm_eh/boilstream.duckdb_extension.wasm`
- Size: 318 KB (wasm_threads version)
- Built for: DuckDB v1.4.1
- Format: wasm_eh (exception handling)

### DuckDB WASM
- Version: Latest from CDN (@duckdb/duckdb-wasm@latest)
- Based on: DuckDB v1.4.1
- Format: wasm_eh (auto-detected)
- Bundle: `duckdb-browser-eh.worker.js`

## Test Flow

```
1. Load DuckDB WASM from CDN ✅
2. Create worker with blob URL ✅
3. Instantiate DuckDB ✅
4. Open with allowUnsignedExtensions=true ✅
5. Connect to database ✅
6. Run basic query (SELECT 42) ✅
7. Fetch extension from http://localhost:8080 ✅
8. INSTALL extension ✅
9. LOAD extension ❌ <- Fails here with LinkError
```

## Next Steps to Debug

### Option 1: Check Build Compatibility
```bash
# Verify extension was built with correct flags
cd build/wasm_eh
wasm-objdump -x extension/boilstream/boilstream.duckdb_extension.wasm | grep import

# Check what symbols the extension expects
nm build/wasm_eh/extension/boilstream/boilstream.duckdb_extension.wasm | grep InternalException
```

### Option 2: Build Extension with Exact DuckDB WASM Configuration

The extension needs to be built using the **exact same configuration** as DuckDB WASM:
- Same Emscripten version
- Same compiler flags
- Same DuckDB source version
- Same exception handling mode

Check DuckDB WASM build configuration:
- https://github.com/duckdb/duckdb-wasm/blob/main/Makefile
- https://github.com/duckdb/duckdb-wasm/blob/main/.github/workflows/

### Option 3: Try Different WASM Format

Currently using `wasm_eh`. Try:
- `wasm_mvp` (simpler, no exception handling)
- `wasm_threads` (with threading support)

### Option 4: Verify DuckDB Version Match

Check the actual DuckDB version used by duckdb-wasm:
```javascript
const version = await conn.query("SELECT version()");
console.log(version);
```

Compare with extension build version.

## Test Commands

### Start Server
```bash
cd test/wasm
npm run serve
```

### Open Test
```
http://localhost:8080/test-wasm-browser.html
```

### Check Extension File
```bash
ls -lh build/wasm_eh/repository/v1.4.1/wasm_eh/boilstream.duckdb_extension.wasm
```

## Files

- `test-wasm-browser.html` - Browser test with detailed logging
- `server.js` - HTTP server with CORS and WASM headers
- `package.json` - Dependencies and scripts
- `README.md` - Full documentation

## Conclusion

The test infrastructure is working perfectly. The issue is an **ABI compatibility problem** between the extension build and DuckDB WASM. The extension needs to be rebuilt using the exact same build configuration as DuckDB WASM to ensure symbol compatibility.

The error is not in the test setup but in the extension build process itself.

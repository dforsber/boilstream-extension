# Instructions to Rebuild Extension with Correct WASM Flags

## Critical Requirements for WASM Build

To build a DuckDB WASM extension that loads successfully, you need:

1. **Emscripten 3.1.71** (exact version used by DuckDB WASM CI)
2. **DuckDB v1.4.1** (latest tag matching duckdb-wasm@latest)
3. **C++ Standard: C++11** (DuckDB default - do NOT use C++17)
4. **WASM Build Flags** (detailed below)

## What Was Fixed

Updated `CMakeLists.txt` to include the **critical WASM flags** that DuckDB extensions need:

### Added Compile Definitions
- `WASM_LOADABLE_EXTENSIONS=1` - Required for all WASM extensions
- `WEBDB_FAST_EXCEPTIONS=1` - For wasm_eh builds
- Exception handling flags: `-fwasm-exceptions`

### Flags by Build Type
- **wasm_eh**: `-fwasm-exceptions` + `WEBDB_FAST_EXCEPTIONS=1`
- **wasm_threads**: `-pthread` + threading/SIMD definitions
- **wasm_mvp**: Base flags only

These flags ensure ABI compatibility with DuckDB WASM runtime.

## Rebuild Commands

### 1. Install and Activate Correct Emscripten Version

**CRITICAL**: Use Emscripten 3.1.71 (same version as DuckDB WASM CI)

```bash
# Install specific version
cd ~/emsdk
./emsdk install 3.1.71
./emsdk activate 3.1.71

# Activate in current shell
source ~/emsdk/emsdk_env.sh

# Verify version
emcc --version  # Should show 3.1.71
```

### 2. Build Extension

**Option A: Use the build script (recommended)**
```bash
cd /Users/dforsber/Desktop/Projektit/GitHub/boilstream-extension
./build-wasm.sh
```

**Option B: Manual build**
```bash
cd /Users/dforsber/Desktop/Projektit/GitHub/boilstream-extension

# Clean old build
rm -rf build/wasm_eh

# Set build type environment variable
export WASM_BUILD_TYPE=wasm_eh

# Build (wasm-opt error is expected but file is still created)
make wasm_eh

# Copy to repository location (required for testing)
mkdir -p build/wasm_eh/repository/v1.4.1/wasm_eh
cp build/wasm_eh/extension/boilstream/boilstream.duckdb_extension.wasm \
   build/wasm_eh/repository/v1.4.1/wasm_eh/
```

**Note**: The build will show a wasm-opt error about `--enable-bulk-memory-opt`
not being recognized in Emscripten 3.1.71. This is expected - the .wasm file is
still created successfully before the optimization step fails.

### 3. Verify Build

```bash
ls -lh build/wasm_eh/repository/v1.4.1/wasm_eh/boilstream.duckdb_extension.wasm
```

### 4. Test in Browser

```bash
cd test/wasm
npm run serve
```

Then open: http://localhost:8080/test-wasm-browser.html

## What Changed in CMakeLists.txt

### Before (WRONG):
```cmake
if(EMSCRIPTEN OR CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
    set(IS_WASM_BUILD ON)
    # Just set -O1 flags - MISSING critical WASM definitions
    set(CMAKE_CXX_FLAGS_RELEASE "-O1 -DNDEBUG" CACHE STRING ...)
endif()
```

### After (CORRECT):
```cmake
if(EMSCRIPTEN OR CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
    set(IS_WASM_BUILD ON)

    # Add DuckDB extension requirements
    add_compile_definitions(WASM_LOADABLE_EXTENSIONS=1)

    # Add build-type specific flags
    if(DEFINED ENV{WASM_BUILD_TYPE})
        if($ENV{WASM_BUILD_TYPE} STREQUAL "wasm_eh")
            add_compile_options(-fwasm-exceptions)
            add_compile_definitions(WEBDB_FAST_EXCEPTIONS=1)
        elseif($ENV{WASM_BUILD_TYPE} STREQUAL "wasm_threads")
            add_compile_options(-pthread)
            add_compile_definitions(WITH_WASM_THREADS=1 ...)
        endif()
    endif()
endif()
```

Plus matching link options.

## Reference

These flags match what the **a5 extension** (proven working) uses:
- https://github.com/query-farm/a5
- Based on DuckDB extension-ci-tools standard Makefile

## Expected Result

After rebuild with correct flags:
- ✅ Extension symbols will match DuckDB WASM runtime
- ✅ No more `LinkError: imported function does not match`
- ✅ Extension loads successfully in browser
- ✅ OPAQUE authentication works in WASM

## Troubleshooting

### If build fails with "emcmake: command not found"
```bash
source ~/emsdk/emsdk_env.sh
```

### If you get symbol mismatches after rebuild
Check that:
1. `WASM_BUILD_TYPE=wasm_eh` was set before building
2. The build output shows: `WASM: Using exception handling mode (wasm_eh)`
3. You're loading the correct format in browser (test detects automatically)

### To rebuild other formats
```bash
# For wasm_threads
export WASM_BUILD_TYPE=wasm_threads
make wasm_threads

# For wasm_mvp
export WASM_BUILD_TYPE=wasm_mvp
make wasm_mvp
```

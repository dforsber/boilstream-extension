# DuckDB WASM + Boilstream Extension Tests

This directory contains tests for the boilstream DuckDB extension in both native and WASM environments.

## Overview

- **Native Extension Testing**: Use Node.js with native DuckDB to test the osx_arm64 extension
- **WASM Extension Testing**: Use browser with duckdb-wasm to test the WASM extension

## Important: WASM vs Native

⚠️ **The native Node.js `duckdb` package CANNOT load WASM extensions!**

- Native `duckdb` package expects platform-specific binaries (e.g., `osx_arm64`)
- WASM extensions must be loaded in `@duckdb/duckdb-wasm` (browser environment)

## Setup

```bash
npm install
```

## WASM Extension Testing (Browser)

### Start the Test Server

```bash
npm run serve
```

This starts an HTTP server at `http://localhost:8080`

### Run the Test

1. Open your browser to: http://localhost:8080/test-wasm-browser.html
2. Click the **"Run Test"** button
3. Watch the log output

### What the Test Does

1. ✅ Loads DuckDB WASM from CDN
2. ✅ Creates a worker and instantiates DuckDB
3. ✅ Runs a basic query (`SELECT 42`)
4. ⏳ Attempts to load the boilstream extension

### Expected Results

**If extension is properly set up:**
```
✅ SUCCESS: Boilstream extension is loaded and ready!
```

**If extension needs setup:**
```
⚠️  DuckDB works, extension loading needs setup
```

## Extension Repository Setup

For the WASM extension to load, it must be in the DuckDB extension repository format:

```
build/wasm_threads/repository/
└── v1.4.1/
    └── wasm_threads/
        ├── boilstream.duckdb_extension.wasm
        └── boilstream.duckdb_extension.info  (optional metadata)
```

This structure is created automatically when you build with:
```bash
make wasm_mvp
# or
make wasm_threads
```

## Native Extension Testing (Node.js)

⚠️ **Note**: This tests the NATIVE extension, not WASM!

```bash
npm test
```

This uses the native `duckdb` package and loads:
```
build/release/repository/v1.4.1/osx_arm64/boilstream.duckdb_extension
```

## Files

- `test-wasm-browser.html` - Browser-based test for WASM extension
- `server.js` - Simple HTTP server for serving the test
- `test-native.js` - Node.js test for native extension (for comparison)
- `package.json` - Dependencies and scripts

## Architecture

### WASM Extension Loading

```
┌─────────────────────────────────────────────────────┐
│  Browser                                            │
│  ┌───────────────────────────────────────────────┐ │
│  │  @duckdb/duckdb-wasm                          │ │
│  │  (from CDN: jsdelivr.net)                     │ │
│  └───────────────────────────────────────────────┘ │
│                     ↓                               │
│  ┌───────────────────────────────────────────────┐ │
│  │  LOAD boilstream                              │ │
│  └───────────────────────────────────────────────┘ │
│                     ↓                               │
│  ┌───────────────────────────────────────────────┐ │
│  │  Fetch from repository:                       │ │
│  │  /build/wasm_threads/repository/v1.4.1/       │ │
│  │         wasm_threads/boilstream.wasm          │ │
│  └───────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

### Why a Web Server?

The test needs a web server because:

1. **CORS**: WASM files must be served with proper headers
2. **File Access**: Browsers can't access local files via `file://` protocol
3. **Extension Loading**: DuckDB needs to fetch the extension via HTTP

## Troubleshooting

### Extension Not Loading

**Error**: `Extension 'boilstream' not found`

**Solution**:
1. Build the WASM extension: `make wasm_threads`
2. Verify the file exists:
   ```bash
   ls build/wasm_threads/repository/v1.4.1/wasm_threads/boilstream.duckdb_extension.wasm
   ```
3. Restart the server: `npm run serve`

### CORS Errors

**Error**: `Cross-Origin Request Blocked`

**Solution**: Make sure you're accessing via `http://localhost:8080`, not `file://`

### Worker Errors

**Error**: `SharedArrayBuffer is not defined`

**Solution**: The server sets the required headers automatically:
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Embedder-Policy: require-corp`

If you're using a different server, add these headers.

## Next Steps

Once the extension loads successfully:

1. Test the PRAGMA command:
   ```javascript
   await conn.query("PRAGMA duckdb_secrets_boilstream_endpoint('https://localhost/secrets:TOKEN')");
   ```

2. Test secret retrieval functions

3. Integration testing with real boilstream server

## Package Versions

- `@duckdb/duckdb-wasm`: v1.31.0 (browser WASM, based on DuckDB v1.4.0)
- `duckdb`: v1.4.1 (native Node.js, for comparison testing)

Both are compatible with DuckDB v1.4.x extensions.

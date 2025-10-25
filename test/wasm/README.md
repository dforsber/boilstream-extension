# DuckDB WASM Extension Tests

This directory contains Node.js tests for the boilstream DuckDB extension.

## Current Status

✅ **Basic DuckDB Test Working** - We have successfully set up a Node.js environment that can run DuckDB queries.

## Test Files

- `test-native.js` - Basic test using native DuckDB package (currently working)
- `package.json` - Node.js package configuration
- `test-basic.js` - Attempted @duckdb/duckdb-wasm test (has compatibility issues with Node.js)
- `test-wasm-simple.js` - Attempted simplified WASM test (not working yet)

## Setup

```bash
npm install
```

## Running Tests

```bash
npm test
```

## Current Test Output

```
╔════════════════════════════════════════════════════════════╗
║  DuckDB Native Test (Node.js)                            ║
╚════════════════════════════════════════════════════════════╝

ℹ Step 1: Creating DuckDB instance...
✓ Database created

ℹ Step 2: Opening connection...
✓ Query executed successfully

ℹ Step 3: Reading results...
✓ Result: [{"answer":42}]

✅ Test PASSED: Got expected result (42)

ℹ Step 4: Cleanup...
✓ Cleanup completed

╔════════════════════════════════════════════════════════════╗
║  ✅ All tests passed!                                     ║
╚════════════════════════════════════════════════════════════╝
```

## Next Steps

### 1. Load WASM Extension

Once we have the boilstream extension built as WASM, we can load it using:

```javascript
db.all("INSTALL '/path/to/boilstream.duckdb_extension.wasm'", (err) => {
  if (err) throw err;
  db.all("LOAD boilstream", (err) => {
    // Extension is now loaded
  });
});
```

### 2. Test Boilstream Functions

After loading the extension, test the PRAGMA command:

```javascript
db.all("PRAGMA duckdb_secrets_boilstream_endpoint('https://localhost/secrets:TOKEN')", (err, result) => {
  // Should successfully authenticate via OPAQUE
});
```

### 3. Integration Tests

- Test full OPAQUE authentication flow
- Test secret retrieval
- Test error handling

## Notes on @duckdb/duckdb-wasm

The `@duckdb/duckdb-wasm` package has some compatibility issues when running in Node.js:

1. Worker API differences between browser and Node.js
2. Apache Arrow result processing issues
3. Blob URL support missing in Node.js

For server-side testing, the native `duckdb` package works much better. The WASM version is primarily designed for browser environments.

## Package Versions

- `duckdb`: v1.4.1 (native Node.js binding)
- `@duckdb/duckdb-wasm`: v1.31.0 (browser-focused WASM version)

Both are based on DuckDB v1.4.x, ensuring compatibility with our extension.

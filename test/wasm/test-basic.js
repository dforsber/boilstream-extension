#!/usr/bin/env node

/**
 * Basic DuckDB-WASM Test in Node.js
 *
 * This test verifies that duckdb-wasm works in Node.js environment
 * by running a simple SELECT 42 query.
 *
 * Usage:
 *   npm install
 *   npm test
 */

import * as duckdb from '@duckdb/duckdb-wasm';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Colors for output
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
};

function log(msg, color = colors.reset) {
  console.log(color + msg + colors.reset);
}

async function testBasicQuery() {
  log('\n╔════════════════════════════════════════════════════════════╗', colors.blue);
  log('║  DuckDB-WASM Basic Test (Node.js)                        ║', colors.blue);
  log('╚════════════════════════════════════════════════════════════╝\n', colors.blue);

  try {
    log('ℹ Step 1: Loading DuckDB-WASM module...', colors.blue);

    // Use Node.js blocking version (no workers needed)
    const DUCKDB_DIST = path.join(__dirname, 'node_modules', '@duckdb', 'duckdb-wasm', 'dist');
    const WASM_PATH = path.join(DUCKDB_DIST, 'duckdb-eh.wasm');

    log(`  WASM file: ${path.basename(WASM_PATH)}`, colors.blue);

    log('\nℹ Step 2: Reading WASM binary...', colors.blue);

    // Read WASM file as buffer
    const wasmBinary = fs.readFileSync(WASM_PATH);

    log(`✓ WASM binary loaded (${wasmBinary.length} bytes)`, colors.green);

    log('\nℹ Step 3: Instantiating DuckDB (blocking mode)...', colors.blue);

    const logger = new duckdb.ConsoleLogger(duckdb.LogLevel.WARNING);
    const db = new duckdb.AsyncDuckDB(logger);
    await db.instantiate(wasmBinary);

    log('✓ DuckDB instantiated', colors.green);

    log('\nℹ Step 4: Opening connection...', colors.blue);

    const conn = await db.connect();

    log('✓ Connection opened', colors.green);

    log('\nℹ Step 5: Running query: SELECT 42;', colors.blue);

    const result = await conn.query('SELECT 42 as answer');

    log('✓ Query executed successfully', colors.green);

    log('\nℹ Step 6: Reading results...', colors.blue);

    // Convert result to array
    const rows = result.toArray();

    log(`✓ Result: ${JSON.stringify(rows)}`, colors.green);

    // Verify the result
    if (rows.length === 1 && rows[0].answer === 42) {
      log('\n✅ Test PASSED: Got expected result (42)', colors.green);
    } else {
      log(`\n❌ Test FAILED: Expected [{answer: 42}], got ${JSON.stringify(rows)}`, colors.red);
      process.exit(1);
    }

    log('\nℹ Step 7: Cleanup...', colors.blue);

    await conn.close();
    await db.terminate();

    log('✓ Cleanup completed', colors.green);

    log('\n╔════════════════════════════════════════════════════════════╗', colors.green);
    log('║  ✅ All tests passed!                                     ║', colors.green);
    log('╚════════════════════════════════════════════════════════════╝\n', colors.green);

  } catch (error) {
    log(`\n✗ Test failed: ${error.message}`, colors.red);
    if (error.stack) {
      log(`  ${error.stack}`, colors.red);
    }
    process.exit(1);
  }
}

// Run the test
testBasicQuery().catch(err => {
  console.error(err);
  process.exit(1);
});

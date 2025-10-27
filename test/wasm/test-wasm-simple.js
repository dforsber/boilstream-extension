#!/usr/bin/env node

/**
 * Minimal DuckDB-WASM Test using CommonJS blocking API
 */

import { createRequire } from 'module';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Colors
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

async function test() {
  log('\n╔════════════════════════════════════════════════════════════╗', colors.blue);
  log('║  DuckDB-WASM Test (Blocking API)                         ║', colors.blue);
  log('╚════════════════════════════════════════════════════════════╝\n', colors.blue);

  try {
    log('ℹ Step 1: Loading DuckDB-WASM blocking module...', colors.blue);

    // Use the blocking (synchronous) Node.js version
    const duckdb = require('@duckdb/duckdb-wasm/dist/duckdb-node-blocking.cjs');

    log('✓ Module loaded', colors.green);

    log('\nℹ Step 2: Reading WASM binary...', colors.blue);

    const WASM_PATH = path.join(__dirname, 'node_modules', '@duckdb', 'duckdb-wasm', 'dist', 'duckdb-eh.wasm');
    const wasmBinary = fs.readFileSync(WASM_PATH);

    log(`✓ WASM binary loaded (${wasmBinary.length} bytes)`, colors.green);

    log('\nℹ Step 3: Instantiating DuckDB...', colors.blue);

    const db = new duckdb.DuckDBBindings();
    await db.instantiate(wasmBinary);

    log('✓ DuckDB instantiated', colors.green);

    log('\nℹ Step 4: Opening connection...', colors.blue);

    await db.open(':memory:');

    log('✓ Connection opened', colors.green);

    log('\nℹ Step 5: Running query: SELECT 42;', colors.blue);

    const conn = await db.connect();
    const result = await conn.query('SELECT 42 as answer');

    log('✓ Query executed', colors.green);

    log('\nℹ Step 6: Reading results...', colors.blue);

    const rows = result.toArray();

    log(`✓ Result: ${JSON.stringify(rows)}`, colors.green);

    // Verify
    if (rows.length === 1 && rows[0].answer === 42) {
      log('\n✅ Test PASSED!', colors.green);
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

test().catch(err => {
  console.error(err);
  process.exit(1);
});

#!/usr/bin/env node

/**
 * Basic DuckDB Native Test in Node.js
 *
 * This test verifies that the native duckdb package works
 * by running a simple SELECT 42 query. Once this works, we'll
 * adapt it to load the WASM extension.
 *
 * Usage:
 *   npm install
 *   node test-native.js
 */

import duckdb from 'duckdb';

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
  log('║  DuckDB Native Test (Node.js)                            ║', colors.blue);
  log('╚════════════════════════════════════════════════════════════╝\n', colors.blue);

  return new Promise((resolve, reject) => {
    try {
      log('ℹ Step 1: Creating DuckDB instance...', colors.blue);

      const db = new duckdb.Database(':memory:');

      log('✓ Database created', colors.green);

      log('\nℹ Step 2: Opening connection...', colors.blue);

      db.all('SELECT 42 as answer', (err, rows) => {
        if (err) {
          log(`\n✗ Query failed: ${err.message}`, colors.red);
          db.close();
          reject(err);
          return;
        }

        log('✓ Query executed successfully', colors.green);

        log('\nℹ Step 3: Reading results...', colors.blue);

        log(`✓ Result: ${JSON.stringify(rows)}`, colors.green);

        // Verify the result
        if (rows.length === 1 && rows[0].answer === 42) {
          log('\n✅ Test PASSED: Got expected result (42)', colors.green);
        } else {
          log(`\n❌ Test FAILED: Expected [{answer: 42}], got ${JSON.stringify(rows)}`, colors.red);
          db.close();
          process.exit(1);
        }

        log('\nℹ Step 4: Cleanup...', colors.blue);

        db.close();

        log('✓ Cleanup completed', colors.green);

        log('\n╔════════════════════════════════════════════════════════════╗', colors.green);
        log('║  ✅ All tests passed!                                     ║', colors.green);
        log('╚════════════════════════════════════════════════════════════╝\n', colors.green);

        resolve();
      });

    } catch (error) {
      log(`\n✗ Test failed: ${error.message}`, colors.red);
      if (error.stack) {
        log(`  ${error.stack}`, colors.red);
      }
      reject(error);
    }
  });
}

// Run the test
testBasicQuery().catch(err => {
  console.error(err);
  process.exit(1);
});

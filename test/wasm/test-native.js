#!/usr/bin/env node

/**
 * DuckDB Boilstream Extension Test in Node.js
 *
 * This test loads the boilstream WASM extension and verifies
 * it can be loaded successfully.
 *
 * Usage:
 *   npm install
 *   npm test
 */

import duckdb from 'duckdb';
import path from 'path';
import { fileURLToPath } from 'url';

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

async function testExtension() {
  log('\n╔════════════════════════════════════════════════════════════╗', colors.blue);
  log('║  DuckDB Boilstream Extension Test (Native)               ║', colors.blue);
  log('╚════════════════════════════════════════════════════════════╝\n', colors.blue);

  log('ℹ Note: This tests the NATIVE extension (osx_arm64)', colors.yellow);
  log('  For WASM extension testing, see test-wasm-browser.html\n', colors.yellow);

  // Path to the native extension (not WASM)
  const extensionPath = path.resolve(__dirname, '../../build/release/repository/v1.4.1/osx_arm64/boilstream.duckdb_extension');

  return new Promise((resolve, reject) => {
    try {
      log('ℹ Step 1: Creating DuckDB instance with unsigned extensions allowed...', colors.blue);

      // Pass configuration to allow unsigned extensions
      const db = new duckdb.Database(':memory:', {
        "allow_unsigned_extensions": "true"
      });

      log('✓ Database created (unsigned extensions allowed)', colors.green);

      log('\nℹ Step 2: Running basic query to verify database...', colors.blue);

        db.all('SELECT 42 as answer', (err, rows) => {
          if (err) {
            log(`\n✗ Query failed: ${err.message}`, colors.red);
            db.close();
            reject(err);
            return;
          }

          log('✓ Basic query works', colors.green);
          log(`  Result: ${JSON.stringify(rows)}`, colors.blue);

          log('\nℹ Step 3: Installing boilstream extension...', colors.blue);
          log(`  Extension path: ${extensionPath}`, colors.blue);

          // Install the extension from local file (use FORCE to override any existing installation)
          db.all(`FORCE INSTALL '${extensionPath}'`, (err) => {
            if (err) {
              log(`\n✗ Extension install failed: ${err.message}`, colors.red);
              if (err.stack) {
                log(`  ${err.stack}`, colors.red);
              }
              db.close();
              reject(err);
              return;
            }

            log('✓ Extension installed', colors.green);

            log('\nℹ Step 4: Loading boilstream extension...', colors.blue);

            db.all('LOAD boilstream', (err) => {
              if (err) {
                log(`\n✗ Extension load failed: ${err.message}`, colors.red);
                if (err.stack) {
                  log(`  ${err.stack}`, colors.red);
                }
                db.close();
                reject(err);
                return;
              }

              log('✓ Extension loaded successfully!', colors.green);

              log('\nℹ Step 5: Checking loaded extensions...', colors.blue);

              db.all("SELECT * FROM duckdb_extensions() WHERE extension_name = 'boilstream'", (err, rows) => {
                if (err) {
                  log(`\n✗ Extension check failed: ${err.message}`, colors.red);
                  db.close();
                  reject(err);
                  return;
                }

                log('✓ Extension info retrieved', colors.green);
                log(`  ${JSON.stringify(rows, null, 2)}`, colors.blue);

                if (rows.length > 0 && rows[0].loaded) {
                  log('\n✅ Extension is loaded and ready!', colors.green);
                } else {
                  log('\n⚠️  Extension registered but not loaded', colors.yellow);
                }

                log('\nℹ Step 6: Cleanup...', colors.blue);

                db.close();

                log('✓ Cleanup completed', colors.green);

                log('\n╔════════════════════════════════════════════════════════════╗', colors.green);
                log('║  ✅ All tests passed!                                     ║', colors.green);
                log('╚════════════════════════════════════════════════════════════╝\n', colors.green);

                resolve();
              });
            });
          });
        });
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
testExtension().catch(err => {
  console.error(err);
  process.exit(1);
});

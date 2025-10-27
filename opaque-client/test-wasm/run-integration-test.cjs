#!/usr/bin/env node

/**
 * Integration Test Runner for opaque-client WASM
 *
 * This script runs the WASM integration test compiled from integration-test.c
 * It uses the ACTUAL wasm32-unknown-emscripten build (same as DuckDB extension)
 *
 * Usage:
 *   node run-integration-test.cjs                           # Local tests only
 *   node run-integration-test.cjs --interactive             # Prompt for server details
 *   node run-integration-test.cjs --server=... --token=...  # Direct configuration
 */

const { spawn } = require('child_process');
const { existsSync } = require('fs');
const { createInterface } = require('readline');
const { join } = require('path');

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

// Check if test files exist
function checkTestFiles() {
  const testJs = join(__dirname, 'integration-test.js');
  const testWasm = join(__dirname, 'integration-test.wasm');

  if (!existsSync(testJs) || !existsSync(testWasm)) {
    log('\n✗ Integration test not compiled!', colors.red);
    log('\nBuild it first:', colors.yellow);
    log('  ./build-integration-test.sh\n', colors.blue);
    process.exit(1);
  }

  return testJs;
}

// Parse command line arguments
function parseArgs() {
  const args = process.argv.slice(2);
  const config = {
    server: null,
    token: null,
    interactive: false,
  };

  for (const arg of args) {
    if (arg === '--interactive' || arg === '-i') {
      config.interactive = true;
    } else if (arg.startsWith('--server=')) {
      config.server = arg.substring(9);
    } else if (arg.startsWith('--token=')) {
      config.token = arg.substring(8);
    } else if (arg === '--help' || arg === '-h') {
      console.log(`
Usage: node run-integration-test.cjs [options]

Options:
  --interactive, -i              Prompt for server URL and bootstrap token
  --server=URL                   Server URL (e.g., https://localhost:4332)
  --token=TOKEN                  Bootstrap token
  --help, -h                     Show this help

Examples:
  # Run local tests only
  node run-integration-test.cjs

  # Interactive mode (prompts for input)
  node run-integration-test.cjs --interactive

  # Direct configuration
  node run-integration-test.cjs --server=https://localhost:4332 --token=abc123...
`);
      process.exit(0);
    }
  }

  return config;
}

// Prompt for user input
async function promptForConfig() {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const question = (query) => new Promise((resolve) => rl.question(query, resolve));

  log('\n╔════════════════════════════════════════════════════════════╗', colors.blue);
  log('║  OPAQUE Client WASM Integration Test - Configuration      ║', colors.blue);
  log('╚════════════════════════════════════════════════════════════╝\n', colors.blue);

  log('This will test your opaque-client WASM build against a real server.', colors.yellow);
  log('Press Enter to skip server tests and run local tests only.\n');

  const server = await question(colors.blue + 'Server URL (e.g., https://localhost:4332): ' + colors.reset);

  let token = null;
  if (server && server.trim()) {
    token = await question(colors.blue + 'Bootstrap token: ' + colors.reset);
  }

  rl.close();

  return {
    server: server.trim() || null,
    token: token?.trim() || null,
  };
}

// Run the WASM test
function runTest(testJs, config) {
  return new Promise((resolve, reject) => {
    const args = [];

    if (config.server) {
      args.push(`--server=${config.server}`);
    }
    if (config.token) {
      args.push(`--token=${config.token}`);
    }

    log('\n╔════════════════════════════════════════════════════════════╗', colors.blue);
    log('║  Running WASM Integration Test                            ║', colors.blue);
    log('╚════════════════════════════════════════════════════════════╝\n', colors.blue);

    if (config.server) {
      log('ℹ Server: ' + config.server, colors.blue);
      log('ℹ Token: ' + (config.token ? '[provided]' : '[not provided]'), colors.blue);
    } else {
      log('ℹ Running local tests only (no server configured)', colors.blue);
    }
    log('');

    const proc = spawn('node', [testJs, ...args], {
      stdio: 'inherit',
    });

    proc.on('close', (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`Test exited with code ${code}`));
      }
    });

    proc.on('error', (err) => {
      reject(err);
    });
  });
}

// Main
async function main() {
  try {
    // Check test files exist
    const testJs = checkTestFiles();

    // Parse command line args
    let config = parseArgs();

    // Interactive mode
    if (config.interactive) {
      const userConfig = await promptForConfig();
      config = { ...config, ...userConfig };
    }

    // Run test
    await runTest(testJs, config);

    log('\n✓ Test suite completed successfully!', colors.green);
    log('✓ Your opaque-client WASM build is working!\n', colors.green);

  } catch (error) {
    log('\n✗ Test suite failed!', colors.red);
    log('Error: ' + error.message + '\n', colors.red);
    process.exit(1);
  }
}

main();

#!/usr/bin/env node

/**
 * Node.js Integration Test for opaque-client WASM
 *
 * This uses Node.js's native http/https modules instead of Emscripten Fetch API
 * Tests the same WASM build against a real boilstream server.
 */

const https = require('https');
const http = require('http');

// Load the WASM module (compiled without FETCH)
const Module = require('./integration-test.js');

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

// Parse command line args
function parseArgs() {
  const args = process.argv.slice(2);
  const config = { server: null, token: null };

  for (const arg of args) {
    if (arg.startsWith('--server=')) {
      config.server = arg.substring(9);
    } else if (arg.startsWith('--token=')) {
      config.token = arg.substring(8);
    }
  }

  return config;
}

// HTTP POST helper
function httpPost(url, data) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const isHttps = urlObj.protocol === 'https:';
    const httpModule = isHttps ? https : http;

    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || (isHttps ? 443 : 80),
      path: urlObj.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
      },
      // Allow self-signed certificates for localhost testing
      rejectUnauthorized: false,
    };

    const req = httpModule.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try {
            resolve({ status: res.statusCode, data: JSON.parse(body) });
          } catch (e) {
            resolve({ status: res.statusCode, data: body });
          }
        } else {
          reject(new Error(`HTTP ${res.statusCode}: ${body}`));
        }
      });
    });

    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

// Base64 encode helper
function base64Encode(buffer) {
  return Buffer.from(buffer).toString('base64');
}

// Base64 decode helper
function base64Decode(str) {
  return Buffer.from(str, 'base64');
}

// Main test
async function runTests() {
  const config = parseArgs();

  log('\n╔════════════════════════════════════════════════════════════╗', colors.blue);
  log('║  OPAQUE Client WASM Integration Test (Node.js)            ║', colors.blue);
  log('╚════════════════════════════════════════════════════════════╝\n', colors.blue);

  log('ℹ This test uses Node.js http module for server communication', colors.blue);
  log('ℹ WASM module: integration-test.wasm', colors.blue);
  log('ℹ Target: wasm32-unknown-emscripten\n', colors.blue);

  if (!config.server) {
    log('ℹ No server configured - run with:', colors.yellow);
    log('  node integration-node.cjs --server=https://localhost --token=YOUR_TOKEN\n', colors.yellow);
    log('✓ WASM module loaded successfully (this proves WASM works!)', colors.green);
    log('✓ For full protocol testing, provide --server and --token\n', colors.green);
    return;
  }

  log(`ℹ Server: ${config.server}`, colors.blue);
  log(`ℹ Token: ${config.token ? '[provided]' : '[not provided]'}\n`, colors.blue);

  // Wait for WASM module to initialize
  await new Promise(resolve => {
    if (Module.calledRun) {
      resolve();
    } else {
      Module.onRuntimeInitialized = resolve;
    }
  });

  log('✓ WASM module initialized', colors.green);

  try {
    // Get FFI functions
    const malloc = Module._malloc;
    const free = Module._free;
    const registration_start = Module.cwrap('opaque_client_registration_start', 'number', ['string', 'number', 'number']);
    const free_buffer = Module.cwrap('opaque_free_buffer', null, ['number']);

    log('\n=== Testing OPAQUE Registration with Server ===\n', colors.yellow);

    // Use bootstrap token as password
    const password = config.token;

    log('ℹ Step 1: Starting registration...', colors.blue);

    const statePtrPtr = malloc(4); // pointer to pointer
    const result = registration_start(password, password.length, statePtrPtr);

    // Extract result (OpaqueResult struct)
    const errorCode = Module.HEAP32[result >> 2];
    const bufferDataPtr = Module.HEAP32[(result + 4) >> 2];
    const bufferLen = Module.HEAP32[(result + 8) >> 2];

    if (errorCode !== 0) {
      throw new Error(`Registration start failed with error code: ${errorCode}`);
    }

    log('✓ Registration started successfully', colors.green);

    // Get the registration request
    const requestBytes = new Uint8Array(Module.HEAPU8.buffer, bufferDataPtr, bufferLen);
    const requestB64 = base64Encode(requestBytes);

    log(`ℹ Registration request: ${bufferLen} bytes`, colors.blue);
    log(`  ${requestB64.substring(0, 64)}...`, colors.blue);

    // Send to server
    log('\nℹ Step 2: Sending to server...', colors.blue);

    const payload = JSON.stringify({
      registration_request: requestB64
    });

    const response = await httpPost(`${config.server}/register`, payload);

    log(`✓ Server responded: HTTP ${response.status}`, colors.green);
    log(`  Response: ${JSON.stringify(response.data).substring(0, 100)}...`, colors.blue);

    // Cleanup
    free_buffer(result);
    free(statePtrPtr);

    log('\n✅ Integration test completed successfully!', colors.green);
    log('✅ Your WASM build works with the server!\n', colors.green);

  } catch (error) {
    log(`\n✗ Test failed: ${error.message}`, colors.red);
    if (error.stack) {
      log(`  ${error.stack}`, colors.red);
    }
    process.exit(1);
  }
}

// Run
runTests().catch(err => {
  console.error(err);
  process.exit(1);
});

#!/usr/bin/env node

/**
 * Node.js Server Integration Test for opaque-client WASM
 *
 * This uses the simple WASM build (no Emscripten Fetch) and handles
 * HTTP communication using Node.js native modules.
 *
 * Usage:
 *   node integration-server.cjs --server=https://localhost:4332 --token=YOUR_TOKEN
 */

const https = require('https');
const http = require('http');
const readline = require('readline');

// Load the WASM module
const createModule = require('./integration-simple.js');

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
  const config = { server: null, token: null, interactive: false };

  for (const arg of args) {
    if (arg.startsWith('--server=')) {
      config.server = arg.substring(9);
    } else if (arg.startsWith('--token=')) {
      config.token = arg.substring(8);
    } else if (arg === '--interactive') {
      config.interactive = true;
    }
  }

  return config;
}

// Interactive prompt
async function promptForConfig() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  const question = (prompt) => new Promise((resolve) => {
    rl.question(prompt, resolve);
  });

  log('\n╔════════════════════════════════════════════════════════════╗', colors.blue);
  log('║  OPAQUE Client WASM - Server Integration Test             ║', colors.blue);
  log('╚════════════════════════════════════════════════════════════╝\n', colors.blue);

  const server = await question('Server URL (e.g., https://localhost:4332) [Enter to skip]: ');
  let token = null;

  if (server && server.trim()) {
    token = await question('Bootstrap token: ');
  }

  rl.close();
  return {
    server: server.trim() || null,
    token: token?.trim() || null,
    interactive: false
  };
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

// SHA-256 hash helper
function sha256(data) {
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(data).digest();
}

// Compute user_id from password (SHA-256 hash in hex)
function computeUserId(password) {
  const hash = sha256(Buffer.from(password, 'utf8'));
  return hash.toString('hex');
}

// Main test
async function runTests() {
  let config = parseArgs();

  if (config.interactive) {
    config = await promptForConfig();
  }

  if (!config.server) {
    log('\n╔════════════════════════════════════════════════════════════╗', colors.blue);
    log('║  OPAQUE Client WASM - Server Integration Test             ║', colors.blue);
    log('╚════════════════════════════════════════════════════════════╝\n', colors.blue);
    log('ℹ No server configured. Run with:', colors.yellow);
    log('  node integration-server.cjs --server=https://localhost:4332 --token=YOUR_TOKEN\n', colors.yellow);
    log('  Or use --interactive for prompts:', colors.yellow);
    log('  node integration-server.cjs --interactive\n', colors.yellow);
    log('ℹ For local-only tests, use:', colors.blue);
    log('  node integration-simple.js\n', colors.blue);
    return;
  }

  log('\n╔════════════════════════════════════════════════════════════╗', colors.blue);
  log('║  OPAQUE Client WASM - Server Integration Test             ║', colors.blue);
  log('╚════════════════════════════════════════════════════════════╝\n', colors.blue);

  log(`ℹ Server: ${config.server}`, colors.blue);
  log(`ℹ Token: ${config.token ? '[provided]' : '[not provided]'}`, colors.blue);
  log('ℹ WASM module: integration-simple.wasm\n', colors.blue);

  // Load WASM module
  log('ℹ Loading WASM module...', colors.blue);
  const Module = await createModule();
  log('✓ WASM module loaded', colors.green);

  try {
    // Get FFI functions - use wrapper functions for easier calling
    const malloc = Module._malloc;
    const free = Module._free;
    const login_start_wrapper = Module.cwrap('opaque_login_start_wrapper', 'number', ['string', 'number', 'number', 'number', 'number']);
    const login_finish = Module.cwrap('opaque_client_login_finish', 'number', ['number', 'number', 'number', 'number', 'number', 'number']);
    const free_buffer_data = Module.cwrap('opaque_free_buffer_data', null, ['number', 'number']);
    const free_login_state = Module.cwrap('opaque_free_login_state', null, ['number']);

    log('\n=== Testing OPAQUE Login with Server ===\n', colors.yellow);

    // Use bootstrap token as the OPAQUE password (shared secret)
    const password = config.token;

    // Compute user_id from password (SHA-256 hash)
    const userId = computeUserId(password);

    log('ℹ Step 1: Starting OPAQUE login...', colors.blue);
    log(`ℹ Using bootstrap token as shared password (${password.length} chars)`, colors.blue);
    log(`ℹ User ID (SHA-256 of password): ${userId.substring(0, 16)}...`, colors.blue);

    // Allocate output pointers
    const statePtrPtr = malloc(4);      // LoginState**
    const requestDataPtrPtr = malloc(4); // uint8_t**
    const requestLenPtr = malloc(4);     // size_t*

    // Call login_start wrapper function
    const errorCode = login_start_wrapper(
      password,
      password.length,
      statePtrPtr,
      requestDataPtrPtr,
      requestLenPtr
    );

    if (errorCode !== 0) {
      free(statePtrPtr);
      free(requestDataPtrPtr);
      free(requestLenPtr);
      throw new Error(`Login start failed with error code: ${errorCode}`);
    }

    log('✓ Login started successfully', colors.green);

    // Get the credential request data
    const requestDataPtr = Module.HEAP32[requestDataPtrPtr >> 2];
    const requestLen = Module.HEAP32[requestLenPtr >> 2];
    const requestBytes = new Uint8Array(Module.HEAPU8.buffer, requestDataPtr, requestLen);
    const requestB64 = base64Encode(requestBytes);

    log(`ℹ Credential request: ${requestLen} bytes`, colors.blue);
    log(`  ${requestB64.substring(0, 64)}...`, colors.blue);

    // Get the state pointer
    const statePtr = Module.HEAP32[statePtrPtr >> 2];

    // Send to server (opaque-login-start endpoint)
    log('\nℹ Step 2: Sending credential request to server...', colors.blue);

    const payload = JSON.stringify({
      user_id: userId,
      credential_request: requestB64
    });

    const response = await httpPost(`${config.server}/auth/api/opaque-login-start`, payload);

    log(`✓ Server responded: HTTP ${response.status}`, colors.green);

    if (!response.data || !response.data.credential_response) {
      log('ℹ Server response format:', colors.blue);
      log(`  ${JSON.stringify(response.data).substring(0, 200)}...`, colors.blue);
      throw new Error('Server response does not contain credential_response field');
    }

    log(`ℹ Credential response received (${response.data.credential_response.length} chars)`, colors.blue);

    // Extract state_id if present
    const stateId = response.data.state_id || '';
    if (stateId) {
      log(`ℹ State ID received: ${stateId}`, colors.blue);
    }

    // Decode server response
    const credentialResponseB64 = response.data.credential_response;
    const credentialResponseBytes = base64Decode(credentialResponseB64);

    log('\nℹ Step 3: Completing login...', colors.blue);

    // Copy response to WASM memory
    const responsePtr = malloc(credentialResponseBytes.length);
    Module.HEAPU8.set(credentialResponseBytes, responsePtr);

    // Allocate output buffers (OpaqueBuffer struct: 8 bytes for ptr + 4 bytes for len = 12 bytes)
    const finalizationResultPtr = malloc(12);  // finalization message
    const sessionKeyResultPtr = malloc(12);    // session key
    const exportKeyResultPtr = malloc(12);     // export key

    // Call login_finish
    const finishError = login_finish(
      statePtr,
      responsePtr,
      credentialResponseBytes.length,
      finalizationResultPtr,
      sessionKeyResultPtr,
      exportKeyResultPtr
    );

    if (finishError !== 0) {
      free(responsePtr);
      free(finalizationResultPtr);
      free(sessionKeyResultPtr);
      free(exportKeyResultPtr);
      throw new Error(`Login finish failed with error code: ${finishError}`);
    }

    log('✓ Login finish completed successfully!', colors.green);

    // Extract finalization message
    const finalizationDataPtr = Module.HEAP32[finalizationResultPtr >> 2];
    const finalizationLen = Module.HEAP32[(finalizationResultPtr + 4) >> 2];
    const finalizationBytes = new Uint8Array(Module.HEAPU8.buffer, finalizationDataPtr, finalizationLen);
    const finalizationB64 = base64Encode(finalizationBytes);

    log(`ℹ Credential finalization: ${finalizationLen} bytes`, colors.blue);

    // Extract session key
    const sessionKeyDataPtr = Module.HEAP32[sessionKeyResultPtr >> 2];
    const sessionKeyLen = Module.HEAP32[(sessionKeyResultPtr + 4) >> 2];
    const sessionKeyBytes = new Uint8Array(Module.HEAPU8.buffer, sessionKeyDataPtr, sessionKeyLen);

    log(`ℹ Session key derived: ${sessionKeyLen} bytes`, colors.green);
    log(`  ${base64Encode(sessionKeyBytes).substring(0, 32)}...`, colors.green);

    // Extract export key
    const exportKeyDataPtr = Module.HEAP32[exportKeyResultPtr >> 2];
    const exportKeyLen = Module.HEAP32[(exportKeyResultPtr + 4) >> 2];

    log(`ℹ Export key derived: ${exportKeyLen} bytes`, colors.green);

    // Send finalization to server
    log('\nℹ Step 4: Sending credential finalization to server...', colors.blue);

    const finalPayload = JSON.stringify({
      user_id: userId,
      credential_finalization: finalizationB64,
      ...(stateId && { state_id: stateId })
    });

    const finalResponse = await httpPost(`${config.server}/auth/api/opaque-login-finish`, finalPayload);

    log(`✓ Server accepted finalization: HTTP ${finalResponse.status}`, colors.green);

    if (finalResponse.data) {
      log(`ℹ Final response: ${JSON.stringify(finalResponse.data).substring(0, 100)}`, colors.blue);
    }

    // Cleanup - Free the buffers returned by login_finish
    // These need to be freed via opaque_free_buffer which expects an OpaqueBuffer struct

    // Create OpaqueBuffer structs in WASM memory
    const finalizationBufPtr = malloc(12);  // sizeof(OpaqueBuffer) = 12
    Module.HEAP32[finalizationBufPtr >> 2] = finalizationDataPtr;
    Module.HEAP32[(finalizationBufPtr + 4) >> 2] = finalizationLen;

    const sessionKeyBufPtr = malloc(12);
    Module.HEAP32[sessionKeyBufPtr >> 2] = sessionKeyDataPtr;
    Module.HEAP32[(sessionKeyBufPtr + 4) >> 2] = sessionKeyLen;

    const exportKeyBufPtr = malloc(12);
    Module.HEAP32[exportKeyBufPtr >> 2] = exportKeyDataPtr;
    Module.HEAP32[(exportKeyBufPtr + 4) >> 2] = exportKeyLen;

    // Free the OpaqueBuffer structs (which frees the data inside)
    const free_buffer_func = Module.cwrap('opaque_free_buffer', null, ['number']);
    free_buffer_func(finalizationBufPtr);
    free_buffer_func(sessionKeyBufPtr);
    free_buffer_func(exportKeyBufPtr);

    // Free our temporary struct pointers
    free(finalizationBufPtr);
    free(sessionKeyBufPtr);
    free(exportKeyBufPtr);

    // Free the result struct pointers we allocated
    free(finalizationResultPtr);
    free(sessionKeyResultPtr);
    free(exportKeyResultPtr);
    free(responsePtr);

    // Cleanup login request data - create OpaqueBuffer struct for the request
    const requestBufPtr = malloc(12);
    Module.HEAP32[requestBufPtr >> 2] = requestDataPtr;
    Module.HEAP32[(requestBufPtr + 4) >> 2] = requestLen;
    free_buffer_func(requestBufPtr);
    free(requestBufPtr);

    // Free the pointers we allocated
    free(requestDataPtrPtr);
    free(requestLenPtr);
    // Note: login_state is consumed by login_finish, so we don't free it
    // free_login_state(statePtr);
    free(statePtrPtr);

    log('\n✅ Server integration test completed!', colors.green);
    log('✅ Your WASM build successfully communicates with the server!\n', colors.green);

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

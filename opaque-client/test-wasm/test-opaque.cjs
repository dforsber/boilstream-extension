#!/usr/bin/env node
// Execute the WASM FFI suite; archive existence is not a test result.
const { spawnSync } = require('node:child_process');
const { join } = require('node:path');
const result = spawnSync('bash', [join(__dirname, 'test-ffi.sh')], { stdio: 'inherit' });
if (result.error) console.error(result.error.message);
process.exit(result.status ?? 1);

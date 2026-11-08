import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
// Always ask CMake/Cargo to update the selected tree before loading its output.
// Send build output to stderr: real-server.js reserves stdout for fixture control.
export function ensureWasmBuild(variant) {
  assert(['wasm_eh', 'wasm_threads'].includes(variant), 'Unknown WASM variant');
  execFileSync('bash', [fileURLToPath(new URL('../../build-wasm-fixed.sh', import.meta.url)), variant],
    { stdio: ['ignore', 2, 2] });
}

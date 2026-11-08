import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { readFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
// Ordinary dependency tracking, with explicit source/library selection. Never
// accept an executable merely because an old file exists at the expected path.
export function assertNativeSelection(native) {
  const cache = readFileSync(resolve(native.build, 'CMakeCache.txt'), 'utf8');
  const home = /^CMAKE_HOME_DIRECTORY:INTERNAL=(.+)$/m.exec(cache)?.[1];
  assert(home && realpathSync(home) === realpathSync(native.source),
    'Native library build and source headers must belong to the same selected tree');
  assert.equal(realpathSync(native.extension),
    realpathSync(resolve(native.build, 'extension/boilstream/boilstream.duckdb_extension')),
    'Native extension must belong to the selected build tree');
  assert.equal(resolve(native.driver), resolve(dirname(native.driver), 'native_protocol_driver'));
}
export function ensureNativeBuild(native) {
  assertNativeSelection(native);
  const runnerBuild = dirname(native.driver);
  const run = args => execFileSync('cmake', args, { stdio: ['ignore', 2, 2] });
  run(['-S', fileURLToPath(new URL('../native', import.meta.url)), '-B', runnerBuild,
    `-DDUCKDB_SOURCE_DIR=${native.source}`, `-DDUCKDB_BUILD_DIR=${native.build}`]);
  run(['--build', native.build, '--parallel', '2']);
  run(['--build', runnerBuild, '--parallel', '2']);
}

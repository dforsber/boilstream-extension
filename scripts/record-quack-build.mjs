import { readFile, writeFile, mkdir, copyFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { assertThreadedQuack, quackBuildInputs, sha256 } from '../test/wasm/quack-build.js';
const root = new URL('../', import.meta.url);
const baseline = JSON.parse(await readFile(new URL('test/wasm/baseline.json', root), 'utf8'));
if (!process.argv[2]) throw new Error('Pass the freshly built Quack artifact');
const source = pathToFileURL(process.argv[2]);
const bytes = await readFile(source);
assertThreadedQuack(bytes);
const output = new URL(`build/compatibility/${baseline.engineVersion}/wasm_threads/quack.duckdb_extension.wasm`, root);
await mkdir(dirname(fileURLToPath(output)), { recursive: true });
await copyFile(source, output);
await writeFile(new URL('./quack.build.json', output), JSON.stringify({
  inputs: await quackBuildInputs(baseline), sha256: sha256(bytes),
}, null, 2) + '\n');
console.log(`Built shared-memory Quack: ${fileURLToPath(output)}`);

#!/usr/bin/env node
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { dirname, resolve, basename, extname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';

const here = dirname(fileURLToPath(import.meta.url));
export const baseline = JSON.parse(await readFile(resolve(here, 'baseline.json'), 'utf8'));
export const artifactPath = variant => resolve(process.env.BOILSTREAM_WASM_BUILD_DIR || resolve(here, '../../build'),
  variant, 'extension/boilstream/boilstream.duckdb_extension.wasm');
export const quackArtifactPath = variant => resolve(here, '../../build/compatibility', baseline.engineVersion,
  variant, 'quack.duckdb_extension.wasm');
const dist = resolve(here, 'node_modules/@duckdb/duckdb-wasm/dist');
const publicFiles = new Set(['test-wasm-browser.html', 'suite.js', 'sql-runner.js', 'baseline.json']);
const sqlFiles = new Set(['boilstream_pragmas.test', 'boilstream_grammar.test', 'client_boundary.test']);
const runtimeFiles = new Set(['duckdb-browser.mjs', 'duckdb-base.wasm', 'duckdb-threads.wasm',
  'duckdb-browser-base.worker.js', 'duckdb-browser-threads.worker.js', 'duckdb-browser-threads.pthread.worker.js']);
let bundlePromise;
function browserBundle() {
  bundlePromise ??= build({ entryPoints: [resolve(here, 'suite.js')], bundle: true,
    write: false, format: 'esm', platform: 'browser' }).then(result => result.outputFiles[0].contents);
  return bundlePromise;
}

// Exact route allowlist: no arbitrary repository access and no credential proxy.
export function createTestServer(authFixture) {
  return createServer(async (req, res) => {
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Cache-Control', 'no-store');
    try {
      if (authFixture && await authFixture.handle(req, res)) return;
      if (!['GET', 'HEAD'].includes(req.method)) { res.writeHead(405).end(); return; }
      const route = decodeURIComponent(req.url.split('?')[0]);
      if (route === '/fixtures/corrupt.duckdb_extension.wasm') {
        const content = Buffer.alloc(1024);
        res.writeHead(200, { 'Content-Type': 'application/wasm', 'Content-Length': content.length });
        res.end(req.method === 'HEAD' ? undefined : content);
        return;
      }
      if (route === '/suite.js') {
        const content = await browserBundle();
        res.writeHead(200, { 'Content-Type': 'text/javascript', 'Content-Length': content.length });
        res.end(req.method === 'HEAD' ? undefined : content);
        return;
      }
      let file;
      if (route === '/') file = resolve(here, 'test-wasm-browser.html');
      else if (publicFiles.has(route.slice(1))) file = resolve(here, route.slice(1));
      else if (route.startsWith('/runtime/') && runtimeFiles.has(route.slice(9))) file = resolve(dist, basename(route));
      else if (route.startsWith('/sql/') && sqlFiles.has(route.slice(5))) file = resolve(here, '../sql', basename(route));
      else {
        const match = /^\/extension\/(wasm_eh|wasm_threads)\/boilstream\.duckdb_extension\.wasm$/.exec(route);
        if (match) file = artifactPath(match[1]);
        const quack = /^\/fixtures\/core-extensions\/v2\.0\.0\/(wasm_eh|wasm_threads)\/quack\.duckdb_extension\.wasm$/.exec(route);
        if (quack) file = quackArtifactPath(quack[1]);
      }
      if (!file) { res.writeHead(404).end('Not found'); return; }
      const { size } = await stat(file);
      let start = 0, end = size - 1, status = 200;
      if (req.headers.range) {
        const match = /^bytes=(\d+)-(\d*)$/.exec(req.headers.range);
        start = match ? Number(match[1]) : -1;
        end = match?.[2] ? Math.min(Number(match[2]), size - 1) : size - 1;
        if (!Number.isSafeInteger(start) || start < 0 || start > end) {
          res.writeHead(416, { 'Content-Range': `bytes */${size}` }).end(); return;
        }
        status = 206;
        res.setHeader('Content-Range', `bytes ${start}-${end}/${size}`);
      }
      const types = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript',
        '.wasm': 'application/wasm', '.json': 'application/json' };
      res.writeHead(status, { 'Content-Type': types[extname(file)] || 'text/plain',
        'Content-Length': end - start + 1, 'Accept-Ranges': 'bytes' });
      res.end(req.method === 'HEAD' ? undefined : (await readFile(file)).subarray(start, end + 1));
    } catch (error) {
      if (!res.headersSent) res.writeHead(error.code === 'ENOENT' ? 404 : error instanceof URIError ? 400 : 500);
      res.end('Test resource unavailable');
    }
  });
}

export async function startServer(port = 0, authFixture) {
  await browserBundle();
  const server = createTestServer(authFixture);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  return { server, url: `http://127.0.0.1:${server.address().port}` };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const { url } = await startServer(Number(process.env.PORT || 8080));
  console.log(`WASM tests: ${url}`);
}

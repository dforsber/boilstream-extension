#!/usr/bin/env node

/**
 * Simple HTTP server for testing DuckDB WASM with boilstream extension
 *
 * Usage:
 *   node server.js
 *   Then open http://localhost:8080/test-wasm-browser.html
 */

import { createServer } from 'http';
import { request as httpsRequest } from 'https';
import { readFile } from 'fs/promises';
import { join, dirname, extname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = 8080;
const AUTH_SERVER = 'https://localhost'; // Boilstream auth server

const MIME_TYPES = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.wasm': 'application/wasm',
  '.json': 'application/json',
  '.css': 'text/css',
};

const server = createServer(async (req, res) => {
  try {
    // Remove query string and decode URL
    const url = decodeURIComponent(req.url.split('?')[0]);

    // Security: prevent directory traversal
    if (url.includes('..') && !url.startsWith('/build/')) {
      res.writeHead(403);
      res.end('Forbidden');
      return;
    }

    // Proxy /auth/* requests to boilstream auth server
    if (url.startsWith('/auth/')) {
      console.log(`Proxying: ${req.method} ${url} -> ${AUTH_SERVER}${url}`);

      // Prepare proxy request options
      const proxyOptions = {
        hostname: 'localhost',
        port: 443,
        path: url,
        method: req.method,
        headers: {
          ...req.headers,
          host: 'localhost', // Override host header
        },
        rejectUnauthorized: false, // Allow self-signed certs for localhost testing
      };

      // Create proxy request
      const proxyReq = httpsRequest(proxyOptions, (proxyRes) => {
        // Copy status and headers from proxy response
        res.writeHead(proxyRes.statusCode, proxyRes.headers);

        // Pipe response data
        proxyRes.pipe(res);
      });

      // Handle proxy errors
      proxyReq.on('error', (error) => {
        console.error('Proxy error:', error);
        res.writeHead(502);
        res.end('Bad Gateway - Could not reach auth server');
      });

      // Pipe request data to proxy
      req.pipe(proxyReq);

      return; // Exit early, proxy handles response
    }

    let filePath;

    // Handle build directory access
    if (url.startsWith('/build/')) {
      filePath = join(__dirname, '..', '..', url);
    } else if (url === '/') {
      filePath = join(__dirname, 'test-wasm-browser.html');
    } else {
      filePath = join(__dirname, url);
    }

    console.log(`Request: ${url} -> ${filePath}`);

    const content = await readFile(filePath);
    const ext = extname(filePath);
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    // Add CORS headers for WASM loading
    res.writeHead(200, {
      'Content-Type': contentType,
      'Access-Control-Allow-Origin': '*',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
    });
    res.end(content);

  } catch (error) {
    if (error.code === 'ENOENT') {
      res.writeHead(404);
      res.end('Not Found');
    } else {
      console.error('Server error:', error);
      res.writeHead(500);
      res.end('Internal Server Error');
    }
  }
});

server.listen(PORT, () => {
  console.log(`\n╔════════════════════════════════════════════════════════════╗`);
  console.log(`║  DuckDB WASM Test Server                                  ║`);
  console.log(`╚════════════════════════════════════════════════════════════╝\n`);
  console.log(`Server running at http://localhost:${PORT}/`);
  console.log(`\nOpen in browser: http://localhost:${PORT}/test-wasm-browser.html`);
  console.log(`\nProxy enabled: /auth/* -> ${AUTH_SERVER}/auth/*`);
  console.log(`\nPress Ctrl+C to stop\n`);
});

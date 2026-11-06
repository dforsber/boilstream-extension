// Strict subset used by the shared SQL files. Unknown directives fail closed.
export function parseTests(source) {
  const lines = source.replaceAll('\r\n', '\n').split('\n');
  const tests = [];
  let wasmError;
  for (let i = 0; i < lines.length;) {
    const line = lines[i++].trim();
    if (line.startsWith('# wasm-error:')) {
      if (wasmError !== undefined) throw new Error('Duplicate WASM expectation');
      wasmError = line.slice('# wasm-error:'.length).trim();
      if (!wasmError) throw new Error('Empty WASM expectation');
      continue;
    }
    if (!line || line.startsWith('#') || line === 'require boilstream') continue;
    const parts = line.split(/\s+/);
    if (!['statement', 'query'].includes(parts[0])) throw new Error(`Unsupported directive: ${line}`);
    const test = { kind: parts[0], mode: parts[1], line: i, sql: [], expected: [] };
    if (test.kind === 'statement' && (parts.length !== 2 || !['ok', 'error'].includes(test.mode))) throw new Error(line);
    if (test.kind === 'query') {
      if (!/^[ITR]+$/.test(test.mode)) throw new Error(line);
      if (parts.length > 4 || ['rowsort', 'valuesort'].includes(parts[2])) throw new Error(`Unsupported query options: ${line}`);
      if (parts[2] === 'nosort') {
        if (!parts[3]) throw new Error(`Missing query label: ${line}`);
        test.label = parts[3];
      }
      else if (parts[2]) {
        if (parts.length !== 3) throw new Error(`Unsupported query options: ${line}`);
        test.connection = parts[2];
      }
    }
    while (i < lines.length && lines[i].trim() && lines[i] !== '----') test.sql.push(lines[i++]);
    if (lines[i] === '----') {
      i++;
      while (i < lines.length && lines[i].trim()) test.expected.push(lines[i++]);
    }
    test.sql = test.sql.join('\n');
    if (!test.sql) throw new Error(`Empty SQL at line ${test.line}`);
    if (wasmError !== undefined) {
      if (test.kind !== 'statement' || test.mode !== 'error') throw new Error('WASM expectation requires statement error');
      test.expected = [wasmError];
      wasmError = undefined;
    }
    if (test.mode === 'error' && !test.expected.length) throw new Error('Expected error text is required');
    tests.push(test);
  }
  if (wasmError !== undefined) throw new Error('Orphan WASM expectation');
  if (!tests.length) throw new Error('No SQL regression cases found');
  return tests;
}

function scalar(value) {
  if (value === null) return 'NULL';
  if (typeof value === 'object' && value && Symbol.iterator in value) {
    return '[' + Array.from(value, scalar).join(', ') + ']';
  }
  return String(value);
}

export async function runSqlTests(source, connection, connect, report = () => {}) {
  const named = new Map(), labels = new Map();
  let passed = 0;
  try {
    for (const test of parseTests(source)) {
      let conn = connection;
      if (test.connection) {
        if (!named.has(test.connection)) named.set(test.connection, await connect());
        conn = named.get(test.connection);
      }
      let result, failure;
      try { result = await conn.query(test.sql); } catch (error) { failure = error; }
      const context = `SQL line ${test.line}: ${test.sql}`;
      if (test.kind === 'statement' && test.mode === 'error') {
        if (!failure) throw new Error(`${context}: expected rejection, succeeded`);
        const expected = test.expected.join('\n');
        if (!String(failure.message).includes(expected)) {
          throw new Error(`${context}: expected error containing ${JSON.stringify(expected)}, got ${failure.message}`);
        }
      } else {
        if (failure) throw new Error(`${context}: ${failure.message}`);
        if (test.kind === 'query') {
          const fields = result.schema.fields;
          if (fields.length !== test.mode.length) throw new Error(`${context}: wrong column count`);
          const actual = result.toArray().flatMap(row => fields.map(field => scalar(row[field.name])));
          const expected = test.label && labels.has(test.label) ? labels.get(test.label) : test.expected;
          if (test.label && !labels.has(test.label) && expected.length === 0) {
            if (actual.length === 0) throw new Error(`${context}: reference result must not be empty`);
          } else if (JSON.stringify(actual) !== JSON.stringify(expected)) {
            throw new Error(`${context}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
          }
          if (test.label) labels.set(test.label, actual);
        }
      }
      passed++;
      report(`PASS ${context.split('\n')[0]}`);
    }
  } finally {
    for (const conn of named.values()) await conn.close();
  }
  return passed;
}

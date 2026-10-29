import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { inspect, MAX_FINDINGS } from '../packages/unk-scanner/src/inspect.mjs';
import { inspectBounded } from '../packages/unk-scanner/src/bounded.mjs';

test('worker returns the same findings and contains parser failures', async () => {
  const source = 'navigator.clipboard.writeText("example");';
  assert.deepEqual(await inspectBounded(source), inspect(source));
  await assert.rejects(inspectBounded('const = ;'), /Unexpected/);
  await assert.rejects(inspectBounded('('.repeat(30000)), /nesting|stack/i);
  assert.deepEqual((await inspectBounded('const ok = 1;')).findings, []);
});

test('worker deadline cancels analysis and validates budget', async () => {
  await assert.rejects(inspectBounded('const ok = 1;', { timeoutMs: 1 }), /timed out/);
  await assert.rejects(inspectBounded('', { timeoutMs: 0 }), /Timeout/);
});

test('excessive findings fail explicitly instead of returning an incomplete report', () => {
  assert.throws(() => inspect('"OVERLORD_SERVER_RAW";\n'.repeat(MAX_FINDINGS + 1)), /Finding limit/);
});

test('specific identifier markers are visible without matching comments or generic identifiers', () => {
  assert.equal(inspect('const GUS_UPLOAD_CHUNK_SIZE = 1024;').findings[0].detail, 'GUS_UPLOAD_CHUNK_SIZE');
  assert.deepEqual(inspect('// GUS_UPLOAD_CHUNK_SIZE\nconst CloudStorage = 1;').findings, []);
});

test('gzip CLI keeps input and decoded hashes distinct, rejects bombs and damaged streams', t => {
  const dir = mkdtempSync(join(tmpdir(), 'unk-gzip-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, '-input.js');
  const cli = fileURLToPath(new URL('../packages/unk-scanner/bin/unk-scanner.mjs', import.meta.url));
  const run = args => spawnSync(process.execPath, [cli, ...args], { cwd: dir, encoding: 'utf8', timeout: 15000 });
  const source = Buffer.from('navigator.clipboard.writeText("inert");');
  const compressed = gzipSync(source);
  writeFileSync(file, compressed);
  const raw = run(['--', '-input.js']);
  assert.equal(raw.status, 2);
  assert.match(raw.stderr, /use --gzip/);
  const result = run(['--gzip', '--', '-input.js']);
  assert.equal(result.status, 0, result.stderr);
  const data = JSON.parse(result.stdout);
  assert.equal(data.sha256, createHash('sha256').update(compressed).digest('hex'));
  assert.equal(data.bytes, compressed.length);
  assert.equal(data.decoded.sha256, createHash('sha256').update(source).digest('hex'));
  assert.equal(data.decoded.bytes, source.length);
  assert.equal(data.findings[0].kind, 'clipboard-write');
  for (const bad of [compressed.subarray(0, 12), gzipSync(Buffer.alloc(8 * 1024 * 1024 + 1, 32)), Buffer.from('not gzip')]) {
    writeFileSync(file, bad);
    const failure = run(['--gzip', file]);
    assert.equal(failure.status, 2);
    assert.equal(failure.stdout, '');
  }
});

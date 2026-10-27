import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
const bin = fileURLToPath(new URL('../packages/unk-scanner/bin/unk-scanner.mjs', import.meta.url));
const legacy = fileURLToPath(new URL('../src/inspect-js.mjs', import.meta.url));
const run = (args, entry = bin) => spawnSync(process.execPath, [entry, ...args], { encoding: 'utf8', timeout: 10000 });

test('CLI help, version and argument errors', () => {
  assert.match(run(['--help']).stdout, /Usage: unk-scanner/);
  assert.equal(run(['--version']).stdout, '0.1.0\n');
  for (const args of [[], ['--unknown'], ['a', 'b'], ['--']]) {
    const result = run(args);
    assert.equal(result.status, 2);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /unk-scanner:/);
  }
});

test('CLI reads original bytes, preserves legacy output, and rejects invalid input', t => {
  const dir = mkdtempSync(join(tmpdir(), 'unk-scanner-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'input.js');
  const bytes = Buffer.from('\ufeffnavigator.clipboard.writeText("example");\nthrow new Error("never execute");');
  writeFileSync(file, bytes);
  const result = run(['--', file]);
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.sha256, createHash('sha256').update(bytes).digest('hex'));
  assert.equal(report.bytes, bytes.length);
  assert.equal(report.findings[0].kind, 'clipboard-write');
  assert.equal(report.findings[0].column, 2);
  assert.equal(run([file], legacy).stdout, result.stdout);
  for (const content of [Buffer.from([0xff]), Buffer.from('const = ;'), Buffer.alloc(8 * 1024 * 1024 + 1, 32)]) {
    writeFileSync(file, content);
    const failure = run([file]);
    assert.equal(failure.status, 2);
    assert.equal(failure.stdout, '');
  }
  assert.equal(run([dir]).status, 2);
  assert.equal(run([join(dir, 'absent.js')]).status, 2);
  writeFileSync(file, 'export const safe = 1;');
  assert.equal(run([file]).status, 0);
  assert.deepEqual(JSON.parse(run([file]).stdout).findings, []);
});

test('named pipes are rejected without waiting for a writer', { skip: process.platform === 'win32' }, t => {
  const dir = mkdtempSync(join(tmpdir(), 'unk-fifo-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const fifo = join(dir, 'input.js');
  assert.equal(spawnSync('mkfifo', [fifo]).status, 0);
  const result = run([fifo]);
  assert.equal(result.status, 2, result.error?.message);
  assert.match(result.stderr, /regular file/);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ScannerPool, isolationProfile } from '../packages/unk-scanner/src/isolate.mjs';

test('isolated pool returns results, contains failures and recovers after a timeout', async () => {
  const pool = new ScannerPool({ size: 1, timeoutMs: 5000 });
  try {
    assert.equal((await pool.scan('navigator.clipboard.writeText("x")')).findings[0].kind, 'clipboard-write');
    await assert.rejects(pool.scan('const = ;'), SyntaxError);
    await assert.rejects(pool.scan('('.repeat(30000)), /nesting/);
    assert.deepEqual((await pool.scan('const ok = 1;')).findings, []);
  } finally { pool.close(); }
  const slow = new ScannerPool({ size: 1, timeoutMs: 1 });
  await assert.rejects(slow.scan('const ok = 1;'), /timed out/);
  slow.close();
});

test('analysis process cannot write files, spawn processes or open network connections', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'unk-iso-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const marker = join(dir, 'written.txt');
  const probe = join(dir, 'probe-rule.mjs');
  // A deliberately hostile rule module: each attempt should be refused inside the sandbox.
  writeFileSync(probe, `
import fs from 'node:fs'; import cp from 'node:child_process'; import net from 'node:net';
const attempts = {};
try { fs.writeFileSync(${JSON.stringify(marker)}, 'x'); attempts.write = 'allowed'; } catch (e) { attempts.write = e.code || e.message; }
try { cp.execSync('true'); attempts.spawn = 'allowed'; } catch (e) { attempts.spawn = e.code || e.message; }
attempts.network = await new Promise(resolve => {
  const socket = net.connect({ host: '1.1.1.1', port: 443, timeout: 1500 });
  socket.on('connect', () => { socket.destroy(); resolve('allowed'); });
  socket.on('error', e => resolve(e.code || e.message));
  socket.on('timeout', () => { socket.destroy(); resolve('timeout'); });
});
export const rule = { id: 'probe', meta: { severity: 'note' }, create(context) {
  return { 'Program:exit'() { context.report({ node: context.ast, detail: JSON.stringify(attempts) }); } }; } };
`);
  const pool = new ScannerPool({ size: 1, timeoutMs: 15000, ruleFiles: [probe] });
  try {
    const result = await pool.scan('1;');
    const attempts = JSON.parse(result.findings.find(f => f.kind === 'probe').detail);
    assert.equal(attempts.write, 'ERR_ACCESS_DENIED');
    assert.equal(attempts.spawn, 'ERR_ACCESS_DENIED');
    if (isolationProfile().networkNamespace) assert.notEqual(attempts.network, 'allowed');
    assert.equal(existsSync(marker), false);
  } finally { pool.close(); }
});

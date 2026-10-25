import test from 'node:test';
import assert from 'node:assert/strict';
import { inspect, MAX_BYTES } from '../src/inspect-js.mjs';

test('recognises literal-computed clipboard method and preserves location', () => {
  const result = inspect('\nnavigator.clipboard["write" + "Text"]("training example");');
  assert.deepEqual(result.findings, [{ kind: 'clipboard-write', line: 2, column: 1, detail: 'training example' }]);
  assert.match(result.sha256, /^[a-f0-9]{64}$/);
});
test('optional clipboard chain with dynamic argument remains unresolved', () => {
  const result = inspect('event.clipboardData?.setData("text/plain", makeText());');
  assert.equal(result.findings[0].detail, 'dynamic argument; unresolved');
});
test('comments and unrelated methods do not create clipboard findings', () => {
  assert.deepEqual(inspect('// navigator.clipboard.writeText("x")\nstore.writeText("x");').findings, []);
});
test('finds campaign marker across literal concatenation', () => {
  assert.equal(inspect('const x = "OVERLORD_COMPANY_" + "WALLET_EP";').findings[0].detail, 'OVERLORD_COMPANY_WALLET_EP');
});
test('does not execute submitted code', () => {
  inspect('throw new Error("must never execute"); process.exit(99);');
  assert.equal(process.exitCode, undefined);
});
test('does not infer identifiers or interpolated strings', () => {
  assert.equal(inspect('navigator.clipboard.writeText(`${secret}`);').findings[0].detail, 'dynamic argument; unresolved');
  assert.deepEqual(inspect('const c = navigator.clipboard; c.writeText("x");').findings, []);
});
test('module and script syntax supported; malformed syntax rejected', () => {
  assert.deepEqual(inspect('export const x = 1;').findings, []);
  assert.deepEqual(inspect('with (obj) { x; }').findings, []);
  assert.throws(() => inspect('const = ;'), SyntaxError);
});
test('oversized input rejected before parsing', () => {
  assert.throws(() => inspect(' '.repeat(MAX_BYTES + 1)), /limit/);
});

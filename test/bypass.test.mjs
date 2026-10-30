import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { inspect } from '../packages/unk-scanner/src/inspect.mjs';

// The inert bypass fixtures from the scanner paper (benchmark/bypass). Each
// changes one thing about a detected technique; these tests record which
// changes the rules now absorb and which remain out of scope.
const dir = new URL('../benchmark/bypass/', import.meta.url);
const scan = name => inspect(fs.readFileSync(new URL(name, dir), 'utf8'), { filename: name });
const rank = { none: 0, note: 1, warning: 2, error: 3 };
const severity = (result, kind) => result.findings.filter(f => f.kind === kind)
  .reduce((max, f) => (rank[f.severity] > rank[max] ? f.severity : max), 'none');

for (const name of fs.readdirSync(dir).filter(f => /^[cel]\d.*\.js$/.test(f)).sort()) {
  const kind = { c: 'clickfix-clipboard-command', e: 'electron-run-as-node', l: 'encrypted-loader' }[name[0]];
  // The command text of c7 is fetched at run time and is not in the file.
  const expected = name.startsWith('c7') ? 'none' : 'error';
  test(`${name}: ${kind} ${expected}`, () => assert.equal(severity(scan(name), kind), expected));
}

const decoded = name => {
  const result = scan(name);
  const array = result.deobfuscation[0];
  const strings = result.findings.filter(f => f.kind === 'obfuscated-string-indicator').map(f => f.detail).sort();
  return { array, strings };
};
const baseline = decoded('s0-baseline.js');

test('s0 baseline decodes every call site, including the URL and module name', () => {
  assert.equal(baseline.array.decodedSites, baseline.array.callSites);
  assert.equal(baseline.strings.length, 2);
});

for (const name of ['s1-var-alias.js', 's2-splice-rotation.js', 's3-member-call.js', 's4-dynamic-target.js']) {
  test(`${name}: every call site decoded to the baseline strings`, () => {
    const { array, strings } = decoded(name);
    assert.notEqual(array.method, 'unresolved');
    assert.equal(array.rotation, baseline.array.rotation);
    assert.equal(array.decodedSites, array.callSites);
    assert.equal(array.callSites, baseline.array.callSites);
    assert.deepEqual(strings, baseline.strings);
  });
}

test('an array reordered by unrecognised code is never decoded as unrotated', () => {
  const source = fs.readFileSync(new URL('s2-splice-rotation.js', dir), 'utf8')
    .replaceAll('_0xq.push(_0xq.splice(0,1)[0])', '_0xq.reverse()');
  const array = inspect(source).deobfuscation[0];
  assert.notEqual(array?.method, 'unrotated');
});

test('an extension relaunching its own runtime for a bundled helper stays a warning', () => {
  // Benign shape seen in the calibration corpus: a detached helper server.
  const source = `const cp = require('child_process'), path = require('path');
function startServer(root) {
  const child = cp.spawn(process.execPath, [path.join(root, 'out', 'server.js')],
    { detached: true, stdio: 'ignore', env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' } });
  child.unref();
}
module.exports = { startServer };`;
  assert.equal(severity(inspect(source), 'electron-run-as-node'), 'warning');
});

// Decoder shapes found by the controlled experiment (benchmark/rotation), stored
// as .txt so the test runner never executes them: an
// older release's self-replacing RC4 decoder, and function wrappers that declare
// an offset object before returning.
for (const name of ['v4-self-replacing-rc4.js.txt', 'v5-function-wrappers-calls-transform.js.txt']) {
  test(`obfuscator shape ${name}: strings recovered by checksum`, () => {
    const source = fs.readFileSync(new URL(`fixtures/obfuscator-shapes/${name}`, import.meta.url), 'utf8');
    const result = inspect(source);
    const array = result.deobfuscation[0];
    assert.equal(array.method, 'checksum');
    assert.equal(array.decodedSites, array.callSites);
    const recovered = result.findings.filter(f => f.kind === 'obfuscated-string-indicator').map(f => f.detail).sort();
    assert.deepEqual(recovered, ["https://example.invalid/setup (resolved from string array)", "require('child_process') (resolved from string array)"]);
  });
}

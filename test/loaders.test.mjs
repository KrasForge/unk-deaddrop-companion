import test from 'node:test';
import assert from 'node:assert/strict';
import { inspect } from '../packages/unk-scanner/src/inspect.mjs';

// Inert syntax fixture: intentionally not a working encrypted payload.
const source = `
const payload=Buffer.from("inert fixture","base64");
const iv=payload.subarray(0,12), tag=payload.subarray(12,28), body=payload.subarray(28);
const decoder=crypto.createDecipheriv("aes-256-gcm", key, iv);
decoder.setAuthTag(tag);
const text=Buffer.concat([decoder.update(body), decoder.final()]).toString("utf8");
loader._compile(text, filename);
`;
const matches = input => inspect(input).findings.filter(f => f.kind === 'encrypted-loader');

test('links loader steps with locations and without revealing embedded data', () => {
  const result = matches(source);
  assert.equal(result.length, 1);
  assert.equal(result[0].line, 7);
  assert.deepEqual(result[0].evidence.map(e => e.role),
    ['embedded-payload', 'cipher', 'authentication-tag', 'decrypted-text', 'code-sink']);
  assert.ok(!JSON.stringify(result).includes('inert fixture'));
});

test('variable renaming and computed methods preserve loader match', () => {
  const renamed = source.replaceAll('decoder', 'renamed').replace('._compile', '["_com" + "pile"]');
  assert.equal(matches(renamed).length, 1);
});

test('other ciphers, slices, sinks, scopes and never-reassigned let still match', () => {
  for (const changed of [
    source.replace('decoder.setAuthTag(tag);', ''),
    source.replace('"aes-256-gcm"', '"aes-256-cbc"'),
    source.replace('const iv=payload.subarray(0,12)', 'const iv=payload.subarray(0,16)'),
    source.replace('const text=', 'let text='),
    source.replace('loader._compile(text, filename);', 'require("vm").runInThisContext(text);'),
    source.replace('loader._compile(text, filename);', 'new Function(text)();'),
    'function load(){' + source + '}',
  ]) assert.equal(matches(changed).length, 1, changed);
});

test('encryption or compilation alone and disconnected data do not match', () => {
  for (const changed of [
    source.replace('loader._compile(text, filename);', ''),
    source.replace('loader._compile(text,', 'loader._compile(otherText,'),
    source.replace('decoder.final()', 'unrelated.final()').replace('decoder.update(body)', 'unrelated.update(body)'),
    source.replace('payload.subarray(28)', 'anotherPayload.subarray(28)'),
    source.replace('Buffer.from("inert fixture","base64")', 'readFile(path)'),
    source.replace('"aes-256-gcm"', 'algorithm'),
    source.replace('const text=', 'let text=') + 'text = "";',
  ]) assert.equal(matches(changed).length, 0, changed);
});

test('comments and quoted source are not parsed as loader behavior', () => {
  assert.equal(matches(JSON.stringify(source)).length, 0);
  assert.equal(matches('/*' + source + '*/').length, 0);
});

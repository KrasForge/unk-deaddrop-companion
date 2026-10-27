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
    ['embedded-base64', 'aes-256-gcm', 'authentication-tag', 'decoded-text', 'module-compile']);
  assert.ok(!JSON.stringify(result).includes('inert fixture'));
});

test('variable renaming and computed methods preserve loader match', () => {
  const renamed = source.replaceAll('decoder', 'renamed').replace('._compile', '["_com" + "pile"]');
  assert.equal(matches(renamed).length, 1);
});

test('encryption or compilation alone and disconnected data do not match', () => {
  for (const changed of [
    source.replace('loader._compile(text, filename);', ''),
    source.replace('decoder.setAuthTag(tag);', ''),
    source.replace('loader._compile(text,', 'loader._compile(otherText,'),
    source.replace('decoder.final()', 'unrelated.final()'),
    source.replace('decoder.setAuthTag(tag)', 'unrelated.setAuthTag(tag)'),
    source.replace('payload.subarray(28)', 'anotherPayload.subarray(28)'),
    source.replace('"aes-256-gcm"', '"aes-256-cbc"'),
    source.replace('Buffer.from("inert fixture","base64")', 'readFile(path)'),
    source.replace('const text=', 'let text='),
    source.replace('const iv=payload.subarray(0,12)', 'const iv=payload.subarray(0,16)'),
  ]) assert.equal(matches(changed).length, 0);
});

test('nested functions and out-of-order authentication are not linked', () => {
  assert.equal(matches(source.replace('decoder.setAuthTag(tag);', 'function unused(){decoder.setAuthTag(tag);}')).length, 0);
  assert.equal(matches(source.replace('decoder.setAuthTag(tag);', '') + 'decoder.setAuthTag(tag);').length, 0);
});

test('comments and quoted source are not parsed as loader behavior', () => {
  assert.equal(matches(JSON.stringify(source)).length, 0);
  assert.equal(matches('/*' + source + '*/').length, 0);
});

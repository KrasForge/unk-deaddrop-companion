import test from 'node:test';
import assert from 'node:assert/strict';
import { inspect } from '../packages/unk-scanner/src/inspect.mjs';
import { identifyArtifact } from '../packages/unk-scanner/src/artifacts.mjs';

test('artifact identity preserves the distinction between context and suspect evidence', () => {
  const login = identifyArtifact('5557912dedf7f75666683afbe2632e0b89b8ee23f621432296a9c48eff63e9f4')[0];
  assert.equal(login.classification, 'context-only');
  const polyfill = identifyArtifact('785597bca2e7dd97a652a20a197c077079e635a5663433448e0e1d9fd8c98a64')[0];
  assert.equal(polyfill.classification, 'shared-web-component');
  const extension = identifyArtifact('d5e9288693aa745dc89368deac677e7ea1ec81e663283af30838cdae189b7a7e')[0];
  assert.equal(extension.match, 'exact-source-sha256');
  extension.name = 'changed';
  assert.notEqual(identifyArtifact(extension.sha256)[0].name, 'changed');
});

test('unknown hashes and source containing a known digest do not create identity matches', () => {
  assert.deepEqual(identifyArtifact('0'.repeat(64)), []);
  const result = inspect('"d5e9288693aa745dc89368deac677e7ea1ec81e663283af30838cdae189b7a7e";');
  assert.deepEqual(result.artifactMatches, []);
  assert.deepEqual(result.findings, []);
});

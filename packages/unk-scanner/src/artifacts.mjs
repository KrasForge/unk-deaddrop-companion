// Exact decoded-source identities. These describe retained evidence, not
// generalized malware signatures. Shared web components must not be alerts.
const artifacts = new Map([
  ['5557912dedf7f75666683afbe2632e0b89b8ee23f621432296a9c48eff63e9f4', {
    name: 'Retained Domatisc login interface',
    classification: 'context-only',
    explanation: 'Login and animation code retained from the observed panel. Its content alone does not establish malicious behavior.',
  }],
  ['785597bca2e7dd97a652a20a197c077079e635a5663433448e0e1d9fd8c98a64', {
    name: 'Retained module-preload polyfill',
    classification: 'shared-web-component',
    explanation: 'Generic module-preload compatibility code. An identical copy elsewhere does not establish a campaign association.',
  }],
  ['d5e9288693aa745dc89368deac677e7ea1ec81e663283af30838cdae189b7a7e', {
    name: 'Retained google-dev-tools extension entry point',
    classification: 'known-investigation-artifact',
    explanation: 'Exact retained obfuscated extension source. This match identifies these bytes; the scanner has not resolved its runtime behavior.',
  }],
]);

export function identifyArtifact(sha256) {
  const artifact = artifacts.get(sha256);
  return artifact ? [{ ...artifact, match: 'exact-source-sha256', sha256 }] : [];
}

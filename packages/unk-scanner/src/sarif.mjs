// SARIF 2.1.0 output for code-scanning integrations.
import { relative, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

const SECURITY_SEVERITY = { error: '8.0', warning: '5.0', note: '2.0' };
const HELP = 'https://github.com/KrasForge/unk-deaddrop-companion/blob/main/docs/rules.md';

function uri(path, root) {
  const rel = relative(root, path);
  const value = rel && !rel.startsWith('..') ? rel : path;
  return value.split(sep).map(encodeURIComponent).join('/');
}

export function toSarif(files, { rules, version, root = process.cwd(), isolation }) {
  const ruleIndex = new Map(rules.map((rule, i) => [rule.id, i]));
  const driverRules = rules.map(rule => ({
    id: rule.id,
    name: rule.id.replace(/(^|-)([a-z])/g, (_, __, c) => c.toUpperCase()),
    shortDescription: { text: rule.meta.description ?? rule.id },
    fullDescription: { text: rule.meta.description ?? rule.id },
    defaultConfiguration: { level: rule.meta.severity },
    helpUri: `${HELP}#${rule.id}`,
    properties: {
      tags: ['security', 'javascript', ...(rule.meta.mitre ? [`external/mitre/${rule.meta.mitre}`] : [])],
      'security-severity': SECURITY_SEVERITY[rule.meta.severity],
      precision: rule.meta.severity === 'note' ? 'low' : 'medium',
    },
  }));
  const artifacts = [];
  const results = [];
  const notifications = [];
  for (const file of files) {
    const location = { uri: uri(file.path, root), uriBaseId: '%SRCROOT%' };
    if (file.error) {
      notifications.push({
        level: 'error',
        message: { text: `${file.error}` },
        locations: [{ physicalLocation: { artifactLocation: location } }],
      });
      continue;
    }
    const artifactIndex = artifacts.length;
    artifacts.push({ location, length: file.result.bytes, hashes: { 'sha-256': file.result.sha256 } });
    for (const finding of file.result.findings) {
      const index = ruleIndex.get(finding.kind);
      results.push({
        ruleId: finding.kind,
        ...(index === undefined ? {} : { ruleIndex: index }),
        level: finding.severity,
        message: { text: finding.detail },
        locations: [{
          physicalLocation: {
            artifactLocation: { ...location, index: artifactIndex },
            region: { startLine: finding.line, startColumn: finding.column },
          },
        }],
        partialFingerprints: {
          'unkScanner/v1': `${finding.kind}:${file.result.sha256}:${finding.line}:${finding.column}`,
        },
        ...(finding.via ? { properties: { via: finding.via } } : {}),
      });
    }
  }
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'unk-scanner',
          version,
          semanticVersion: version,
          informationUri: 'https://github.com/KrasForge/unk-deaddrop-companion',
          rules: driverRules,
        },
      },
      originalUriBaseIds: { '%SRCROOT%': { uri: pathToFileURL(root.endsWith(sep) ? root : root + sep).href } },
      artifacts,
      results,
      invocations: [{
        executionSuccessful: notifications.length === 0,
        toolExecutionNotifications: notifications,
        ...(isolation ? { properties: { isolation } } : {}),
      }],
    }],
  };
}

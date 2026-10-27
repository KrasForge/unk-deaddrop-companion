import { identifyArtifact } from './artifacts.mjs';
import { encryptedLoaders } from './loaders.mjs';
import { parse } from 'acorn';
import { createHash } from 'node:crypto';

export const MAX_FINDINGS = 10000;
export const MAX_BYTES = 8 * 1024 * 1024;
const MARKERS = /OVERLORD_COMPANY_WALLET_EP|OVERLORD_SERVER_RAW|OVERLORD_KEEP_AGENT_STATE|X-Company-Wallet-Client-Id|\/api\/company-wallet\/upload|GoogleUpdateSupporterNode|GUS_UPLOAD_CHUNK_SIZE|DEFAULT_PHASE3_MAX_MS|DEFAULT_PHASE3_ROOT_MAX_MS|WIN_NODE_AGENT_BUNDLE_B64|DEFAULT_WALK_MAX_DIRS|CREDENTIAL_NAME_RE|macTccReadableCache|CloudStorage|ELECTRON_RUN_AS_NODE|--company-wallet-phase1-local|--company-wallet-job|--win-build-ep-only|cmdline_copied|perl -MPOSIX|POSIX::setsid|curl -ks|start -WindowStyle Hidden cmd|VERIFY-|IElevator|detect_malware\.py|3E5FC7F9-9A51-4367-9063-A120244FBEC7|gus-phase2-|sa-elev-done-|app_bound_encrypted_key/g;

// Only literal syntax is folded. No variable resolution, calls or coercion.
export function literalString(node, depth = 0) {
  if (!node || depth > 32) return undefined;
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis[0].value.cooked ?? undefined;
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = literalString(node.left, depth + 1);
    const right = literalString(node.right, depth + 1);
    if (left !== undefined && right !== undefined) return left + right;
  }
  return undefined;
}
const IDENTIFIER_MARKERS = new Set([
  'OVERLORD_COMPANY_WALLET_EP', 'OVERLORD_SERVER_RAW', 'OVERLORD_KEEP_AGENT_STATE',
  'GUS_UPLOAD_CHUNK_SIZE', 'DEFAULT_PHASE3_MAX_MS', 'DEFAULT_PHASE3_ROOT_MAX_MS',
  'WIN_NODE_AGENT_BUNDLE_B64', 'DEFAULT_WALK_MAX_DIRS', 'CREDENTIAL_NAME_RE',
  'macTccReadableCache', 'ELECTRON_RUN_AS_NODE', 'app_bound_encrypted_key',
]);

function memberName(node) {
  while (node?.type === 'ChainExpression') node = node.expression;
  if (node?.type !== 'MemberExpression') return undefined;
  return node.computed ? literalString(node.property) : node.property.name;
}

export function inspect(source) {
  if (typeof source !== 'string') throw new TypeError('Expected JavaScript text');
  if (Buffer.byteLength(source) > MAX_BYTES) throw new Error('Input exceeds 8 MiB limit');
  let ast;
  try {
    ast = parse(source, { ecmaVersion: 'latest', sourceType: 'module', locations: true });
  } catch (error) {
    if (!(error instanceof SyntaxError)) throw error;
    ast = parse(source, { ecmaVersion: 'latest', sourceType: 'script', locations: true });
  }
  const findings = [];
  const seen = new Set();
  const add = (kind, node, detail, extra = {}) => {
    const key = `${kind}:${node.start}:${detail}`;
    if (seen.has(key)) return;
    if (findings.length >= MAX_FINDINGS) throw new Error('Finding limit exceeded; no complete result');
    seen.add(key);
    findings.push({ kind, line: node.loc.start.line, column: node.loc.start.column + 1, detail, ...extra });
  };
  const pending = [ast];
  while (pending.length) {
    const node = pending.pop();
    if (node.type === 'Identifier' && IDENTIFIER_MARKERS.has(node.name)) {
      add('campaign-marker', node, node.name);
    }
    const value = literalString(node);
    if (value !== undefined) {
      for (const match of value.matchAll(MARKERS)) add('campaign-marker', node, match[0]);
    }
    if (node.type === 'CallExpression') {
      const callee = node.callee.type === 'ChainExpression' ? node.callee.expression : node.callee;
      const method = memberName(callee);
      const owner = memberName(callee?.object);
      if ((method === 'writeText' && owner === 'clipboard') ||
          (method === 'setData' && owner === 'clipboardData')) {
        const arg = node.arguments[method === 'setData' ? 1 : 0];
        const text = literalString(arg);
        add('clipboard-write', node, text === undefined ? 'dynamic argument; unresolved' : text.slice(0, 240));
      }
    }
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) {
        for (const child of value) if (child?.type) pending.push(child);
      } else if (value?.type) pending.push(value);
    }
  }
  for (const loader of encryptedLoaders(ast, literalString)) {
    add('encrypted-loader', loader.node,
      'Embedded base64, AES-GCM authentication, and decoded text linked syntactically to _compile',
      { evidence: loader.evidence });
  }
  findings.sort((a, b) => a.line - b.line || a.column - b.column || a.kind.localeCompare(b.kind));
  const sha256 = createHash('sha256').update(source).digest('hex');
  return {
    schemaVersion: 1,
    sha256,
    artifactMatches: identifyArtifact(sha256),
    bytes: Buffer.byteLength(source),
    findings,
    limitations: ['Syntactic matches only; no data-flow or reachability proof',
      'No general alias resolution or encoded string-table deobfuscation',
      'Encrypted-loader recognition covers only a specific top-level const-binding pattern',
      'A clipboard write or marker alone is not a maliciousness verdict'],
  };
}

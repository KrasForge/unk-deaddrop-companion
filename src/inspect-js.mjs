#!/usr/bin/env node
import { parse } from 'acorn';
import { createHash } from 'node:crypto';
import { open } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

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

function memberName(node) {
  if (node?.type !== 'MemberExpression') return undefined;
  return node.computed ? literalString(node.property) : node.property.name;
}

export function inspect(source) {
  if (typeof source !== 'string') throw new TypeError('Expected JavaScript text');
  if (Buffer.byteLength(source) > MAX_BYTES) throw new Error('Input exceeds 8 MiB limit');
  let ast;
  try {
    ast = parse(source, { ecmaVersion: 'latest', sourceType: 'module', locations: true });
  } catch {
    ast = parse(source, { ecmaVersion: 'latest', sourceType: 'script', locations: true });
  }
  const findings = [];
  const seen = new Set();
  const add = (kind, node, detail) => {
    const key = `${kind}:${node.start}:${detail}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push({ kind, line: node.loc.start.line, column: node.loc.start.column + 1, detail });
  };
  const pending = [ast];
  while (pending.length) {
    const node = pending.pop();
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
  findings.sort((a, b) => a.line - b.line || a.column - b.column || a.kind.localeCompare(b.kind));
  return {
    schemaVersion: 1,
    sha256: createHash('sha256').update(source).digest('hex'),
    bytes: Buffer.byteLength(source),
    findings,
    limitations: ['Syntactic matches only; no data-flow or reachability proof',
      'No alias resolution or encoded string-table deobfuscation',
      'A clipboard write or marker alone is not a maliciousness verdict'],
  };
}

export async function main(args) {
  if (args.length !== 1) throw new Error('Usage: node src/inspect-js.mjs FILE.js');
  const handle = await open(args[0], 'r');
  let bytes;
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error('Input must be a regular file');
    if (stat.size > MAX_BYTES) throw new Error('Input exceeds 8 MiB limit');
    // Read at most the limit plus one, including if the input grows after stat().
    const buffer = Buffer.alloc(MAX_BYTES + 1);
    let count = 0;
    while (count < buffer.length) {
      const read = await handle.read(buffer, count, buffer.length - count, null);
      if (!read.bytesRead) break;
      count += read.bytesRead;
    }
    if (count > MAX_BYTES) throw new Error('Input exceeds 8 MiB limit');
    bytes = buffer.subarray(0, count);
  } finally {
    await handle.close();
  }
  const source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const result = inspect(source);
  result.sha256 = createHash('sha256').update(bytes).digest('hex');
  result.bytes = bytes.length;
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).catch(error => {
    process.stderr.write(`inspect-js: ${error.message}\n`);
    process.exitCode = 2;
  });
}

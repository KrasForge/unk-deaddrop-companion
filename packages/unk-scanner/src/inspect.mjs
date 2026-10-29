import { identifyArtifact } from './artifacts.mjs';
import { builtinRules } from './rules/index.mjs';
import { Scopes, Evaluator, NO, isFunction, PARENT } from './evaluate.mjs';
import { deobfuscate } from './deobfuscate.mjs';
import { parse } from 'acorn';
import { createHash } from 'node:crypto';

export const MAX_FINDINGS = 10000;
export const MAX_BYTES = 8 * 1024 * 1024;
export const SCHEMA_VERSION = 2;
const SEVERITIES = new Set(['error', 'warning', 'note']);

// Only literal syntax is folded here. Constant propagation and string-array
// recovery live in the evaluator and are exposed to rules separately.
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

// Line and column from a source offset. Acorn location objects triple the
// AST's memory, so positions are computed only for reported nodes.
function positions(source) {
  let starts;
  return offset => {
    if (!starts) {
      starts = [0];
      for (let i = 0; i < source.length; i++) {
        const ch = source.charCodeAt(i);
        if (ch === 10 || ch === 0x2028 || ch === 0x2029 || (ch === 13 && source.charCodeAt(i + 1) !== 10)) starts.push(i + 1);
      }
    }
    let low = 0;
    let high = starts.length - 1;
    while (low < high) {
      const mid = (low + high + 1) >> 1;
      if (starts[mid] <= offset) low = mid; else high = mid - 1;
    }
    return { line: low + 1, column: offset - starts[low] + 1 };
  };
}

// Acorn is recursive-descent: deeply nested input ends in a RangeError, which
// is reported as an error. The scanner's own walkers are iterative and the
// evaluator is depth-capped.
function parseSource(source) {
  try {
    try {
      return parse(source, { ecmaVersion: 'latest', sourceType: 'module' });
    } catch (error) {
      if (!(error instanceof SyntaxError)) throw error;
      return parse(source, { ecmaVersion: 'latest', sourceType: 'script' });
    }
  } catch (error) {
    if (error instanceof RangeError || /^Not enough stack space/.test(error?.message)) {
      throw new Error('Input nesting exceeds parser stack; no result');
    }
    throw error;
  }
}

function index(ast) {
  const order = [];
  const pending = [ast];
  while (pending.length) {
    const node = pending.pop();
    order.push(node);
    for (const key in node) {
      if (key === 'type' || key === 'loc') continue;
      const value = node[key];
      if (Array.isArray(value)) {
        for (let i = value.length - 1; i >= 0; i--) {
          const child = value[i];
          if (child?.type) { child[PARENT] = node; pending.push(child); }
        }
      } else if (value?.type) { value[PARENT] = node; pending.push(value); }
    }
  }
  return order;
}

function validateRule(rule) {
  if (!rule || typeof rule.id !== 'string' || !/^[a-z0-9][a-z0-9-]*$/.test(rule.id) ||
      typeof rule.create !== 'function' || !SEVERITIES.has(rule.meta?.severity)) {
    throw new TypeError(`Invalid rule: ${rule?.id ?? '(unnamed)'}`);
  }
}

class Context {
  constructor(source, ast, order) {
    this.source = source;
    this.ast = ast;
    this.order = order;
    this.scopes = new Scopes();
    this.position = positions(source);
    const recovered = deobfuscate(ast, this.scopes, order);
    this.resolved = recovered.resolved;
    this.deobfuscation = { arrays: recovered.arrays };
    this.evaluator = recovered.evaluator ?? new Evaluator(this.scopes);
    this.info = new Map();
    this.writes = new Map();
    this.covered = new Map();
    this.listeners = undefined;
  }

  parent(node) { return node[PARENT]; }

  visit(root, fn, limit = 2000) {
    const pending = [root];
    let count = 0;
    while (pending.length && count++ < limit) {
      const node = pending.pop();
      if (!node) continue;
      fn(node);
      for (const key in node) {
        if (key === 'type' || key === 'loc') continue;
        const value = node[key];
        if (Array.isArray(value)) { for (const child of value) if (child?.type) pending.push(child); }
        else if (value?.type) pending.push(value);
      }
    }
  }

  // Literal folding plus strings recovered from a string array.
  literalInfo(node, depth = 0) {
    if (!node || depth > 64) return undefined;
    // Fast paths avoid memoizing every node of large bundles.
    if (node.type === 'Literal') return typeof node.value === 'string' ? { value: node.value, deobfuscated: false } : undefined;
    if (node.type !== 'TemplateLiteral' && node.type !== 'BinaryExpression' && node.type !== 'CallExpression' &&
        node.type !== 'MemberExpression') return undefined;
    if (node.type === 'CallExpression' && !this.resolved.size) return undefined;
    if (node.type === 'BinaryExpression' && node.operator !== '+') return undefined;
    if (this.info.has(node)) return this.info.get(node);
    let info;
    if (node.type === 'Literal' && typeof node.value === 'string') info = { value: node.value, deobfuscated: false };
    else if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
      const value = node.quasis[0].value.cooked;
      if (value != null) info = { value, deobfuscated: false };
    } else if (node.type === 'BinaryExpression' && node.operator === '+') {
      const left = this.literalInfo(node.left, depth + 1);
      const right = left && this.literalInfo(node.right, depth + 1);
      if (left && right) info = { value: left.value + right.value, deobfuscated: left.deobfuscated || right.deobfuscated };
    } else if (node.type === 'CallExpression' && this.resolved.has(node)) {
      info = { value: this.resolved.get(node), deobfuscated: true };
    } else if (node.type === 'MemberExpression' && this.resolved.size) {
      const value = this.evaluator.evaluate(node);
      if (typeof value === 'string') info = { value, deobfuscated: true };
    }
    this.info.set(node, info);
    return info;
  }

  literal(node) { return this.literalInfo(node)?.value; }

  // Pure evaluation including constant propagation; undefined if unresolved.
  resolve(node) {
    if (!node) return undefined;
    const info = this.literalInfo(node);
    if (info) return info.value;
    const value = this.evaluator.evaluate(node);
    return value === NO ? undefined : value;
  }

  // String fragments in an expression. Locally defined helpers, and objects
  // of helpers, are followed (bounded) so that command builders are visible.
  // This harvests text only; it is not evaluation.
  fragments(node) {
    const parts = [];
    const seen = new Set();
    let budget = 8000;
    const follow = (binding, depth) => {
      const target = binding?.kind === 'function' ? binding.node.body
        : binding?.kind === 'object' ? binding.node
          : binding?.kind === 'opaque' && (binding.init?.type === 'ObjectExpression' || isFunction(binding.init)) ? binding.init
            : undefined;
      if (!target || seen.has(target)) return;
      seen.add(target);
      collect(target, depth + 1);
    };
    const collect = (root, depth) => {
      const pending = [root];
      while (pending.length && budget-- > 0 && parts.length < 256) {
        const inner = pending.pop();
        if (inner.type === 'Literal' && typeof inner.value === 'string') parts.push(inner.value);
        else if (inner.type === 'TemplateElement' && inner.value.cooked) parts.push(inner.value.cooked);
        else if (inner.type === 'Identifier') {
          if (depth === 0) {
            const value = this.resolve(inner);
            if (typeof value === 'string') { parts.push(value); continue; }
          }
          const parent = this.parent(inner);
          const reference = !(parent?.type === 'MemberExpression' && parent.property === inner && !parent.computed) &&
            !(parent?.type === 'Property' && parent.key === inner);
          if (reference && depth < 6) follow(this.scopes.lookup(inner.name, inner), depth);
        }
        for (const key in inner) {
          if (key === 'type' || key === 'loc') continue;
          const value = inner[key];
          if (Array.isArray(value)) { for (const child of value) if (child?.type) pending.push(child); }
          else if (value?.type) pending.push(value);
        }
      }
    };
    collect(node, 0);
    return parts;
  }

  // Arguments passed for a parameter, found at calls to its function
  // (direct calls by name only; at most 20 call sites).
  callerArguments(node) {
    if (node?.type !== 'Identifier') return [];
    const binding = this.scopes.lookup(node.name, node);
    if (binding?.kind !== 'param') return [];
    const fn = binding.fn;
    const index = fn.params.findIndex(param => param.type === 'Identifier' && param.name === node.name);
    let name = fn.id?.name;
    const holder = fn[PARENT];
    if (!name && holder?.type === 'VariableDeclarator' && holder.id.type === 'Identifier') name = holder.id.name;
    if (!name || index < 0) return [];
    const args = [];
    for (const call of this.order) {
      if (args.length >= 20) break;
      if (call.type !== 'CallExpression' || call.callee.type !== 'Identifier' || call.callee.name !== name) continue;
      const target = this.scopes.lookup(name, call.callee);
      if (target?.kind === 'function' && target.node === fn && call.arguments[index]) args.push(call.arguments[index]);
    }
    return args;
  }

  memberName(node) {
    while (node?.type === 'ChainExpression') node = node.expression;
    if (node?.type !== 'MemberExpression') return undefined;
    if (!node.computed) return node.property.type === 'Identifier' ? node.property.name : undefined;
    return this.literal(node.property);
  }

  clipboardWrite(node) {
    if (this.writes.has(node)) return this.writes.get(node);
    let write;
    if (node.type === 'CallExpression') {
      const callee = node.callee.type === 'ChainExpression' ? node.callee.expression : node.callee;
      const method = this.memberName(callee);
      const owner = this.memberName(callee?.object);
      if ((method === 'writeText' && owner === 'clipboard') || (method === 'setData' && owner === 'clipboardData')) {
        write = { method, arg: node.arguments[method === 'setData' ? 1 : 0] };
      }
    }
    this.writes.set(node, write);
    return write;
  }

  describe(node) {
    if (node?.type === 'Identifier') return node.name;
    if (node?.type === 'MemberExpression') return `${this.describe(node.object)}.${this.memberName(node) ?? '?'}`;
    if (node?.type === 'CallExpression') return `${this.describe(node.callee)}()`;
    return 'object';
  }

  #collectListeners() {
    this.listeners = new Map();
    for (const node of this.order) {
      let handler;
      let event;
      let target;
      if (node.type === 'CallExpression' && ['addEventListener', 'on'].includes(this.memberName(node.callee))) {
        event = this.literal(node.arguments[0]);
        handler = node.arguments[1];
        target = this.describe(node.callee.object);
      } else if (node.type === 'AssignmentExpression' && ['oncopy', 'oncut'].includes(this.memberName(node.left))) {
        event = this.memberName(node.left).slice(2);
        handler = node.right;
        target = this.describe(node.left.object);
      }
      if (!handler || !['copy', 'cut'].includes(event)) continue;
      if (handler.type === 'Identifier') {
        const binding = this.scopes.lookup(handler.name, handler);
        handler = binding?.kind === 'function' ? binding.node : undefined;
      }
      if (handler) this.listeners.set(handler, { event, target });
    }
  }

  copyListener(node) {
    if (!this.listeners) this.#collectListeners();
    if (!this.listeners.size) return undefined;
    for (let current = this.parent(node); current; current = this.parent(current)) {
      const listener = this.listeners.get(current);
      if (listener) return listener;
    }
    return undefined;
  }

  objectOf(node) {
    if (node?.type === 'ObjectExpression') return node;
    if (node?.type === 'Identifier') {
      const binding = this.scopes.lookup(node.name, node);
      if (binding?.kind === 'object') return binding.node;
    }
    return undefined;
  }

  #keyName(property) {
    if (property.type !== 'Property') return undefined;
    if (!property.computed) return property.key.type === 'Identifier' ? property.key.name : String(property.key.value);
    const value = this.resolve(property.key);
    return typeof value === 'string' ? value : undefined;
  }

  propertyValue(object, name) {
    let found;
    for (const property of object.properties) if (this.#keyName(property) === name) found = property.value;
    return found;
  }

  hasProperty(object, name) {
    return object.properties.some(property => this.#keyName(property) === name);
  }

  // Marker de-duplication: true when an enclosing node already reported it.
  coveredBy(node, detail) {
    const ranges = this.covered.get(detail) ?? [];
    if (ranges.some(([start, end]) => node.start >= start && node.end <= end)) return true;
    ranges.push([node.start, node.end]);
    this.covered.set(detail, ranges);
    return false;
  }
}

export function inspect(source, { rules = [] } = {}) {
  if (typeof source !== 'string') throw new TypeError('Expected JavaScript text');
  if (Buffer.byteLength(source) > MAX_BYTES) throw new Error('Input exceeds 8 MiB limit');
  const active = [...builtinRules, ...rules];
  const ids = new Set();
  for (const rule of active) {
    validateRule(rule);
    if (ids.has(rule.id)) throw new TypeError(`Duplicate rule id: ${rule.id}`);
    ids.add(rule.id);
  }
  const ast = parseSource(source);
  const order = index(ast);
  const context = new Context(source, ast, order);
  const findings = [];
  const seen = new Set();
  const visitors = new Map();
  const exits = [];
  for (const rule of active) {
    const report = ({ node, detail, severity, data, via }) => {
      const level = severity ?? rule.meta.severity;
      if (!SEVERITIES.has(level)) throw new TypeError(`Invalid severity from ${rule.id}`);
      const key = `${rule.id}:${node.start}:${detail}`;
      if (seen.has(key)) return;
      if (findings.length >= MAX_FINDINGS) throw new Error('Finding limit exceeded; no complete result');
      seen.add(key);
      findings.push({
        kind: rule.id, severity: level, ...context.position(node.start),
        detail: String(detail), ...(via ? { via } : {}), ...(data ?? {}),
      });
    };
    const ruleContext = Object.create(context, { report: { value: report } });
    for (const name of ['literal', 'literalInfo', 'resolve', 'fragments', 'memberName', 'clipboardWrite',
      'copyListener', 'objectOf', 'propertyValue', 'hasProperty', 'coveredBy', 'parent', 'visit', 'describe', 'position',
      'callerArguments']) {
      Object.defineProperty(ruleContext, name, { value: typeof context[name] === 'function' ? context[name].bind(context) : context[name] });
    }
    const handlers = rule.create(ruleContext) ?? {};
    for (const [type, handler] of Object.entries(handlers)) {
      if (typeof handler !== 'function') continue;
      if (type === 'Program:exit') exits.push(handler);
      else {
        if (!visitors.has(type)) visitors.set(type, []);
        visitors.get(type).push(handler);
      }
    }
  }
  const any = visitors.get('*') ?? [];
  for (const node of order) {
    for (const handler of any) handler(node);
    const typed = visitors.get(node.type);
    if (typed) for (const handler of typed) handler(node);
  }
  for (const handler of exits) handler();
  findings.sort((a, b) => a.line - b.line || a.column - b.column || a.kind.localeCompare(b.kind));
  const sha256 = createHash('sha256').update(source).digest('hex');
  return {
    schemaVersion: SCHEMA_VERSION,
    sha256,
    artifactMatches: identifyArtifact(sha256),
    bytes: Buffer.byteLength(source),
    findings,
    deobfuscation: context.deobfuscation.arrays.map(({ node, ...array }) => ({ ...context.position(node.start), ...array })),
    limitations: [
      'Static analysis only: the input is parsed and partially evaluated, never executed',
      'Constant propagation covers const bindings, literal object properties and single-return helpers; no general data flow or reachability',
      'String-array recovery covers obfuscator.io-style plain, base64 and RC4 decoders',
      'Encrypted-loader recognition covers only a specific top-level const-binding pattern',
      'A finding is a review lead, not a maliciousness verdict',
    ],
  };
}

export { builtinRules };

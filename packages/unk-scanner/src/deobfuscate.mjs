// Static recovery of obfuscator.io-style string arrays. The decoder variants
// (plain, base64, RC4) are reimplemented here; the input's own decoder code is
// only inspected to identify the variant, offset and alphabet.
import { NO, Evaluator, ArraySource, isFunction } from './evaluate.mjs';

const MIN_ARRAY = 5;
const MAX_SITES = 200000;
const MAX_ROTATION_WORK = 400000;
const PRINTABLE = /^[\t\n\r\x20-\x7e -ɏ]+$/;

function walk(root, visit) {
  const pending = [root];
  while (pending.length) {
    const node = pending.pop();
    if (visit(node) === false) continue;
    for (const key in node) {
      if (key === 'type' || key === 'loc') continue;
      const value = node[key];
      if (Array.isArray(value)) { for (const child of value) if (child?.type) pending.push(child); }
      else if (value?.type) pending.push(value);
    }
  }
}

function stringArray(node) {
  if (node?.type !== 'ArrayExpression' || node.elements.length < MIN_ARRAY) return undefined;
  const strings = [];
  for (const element of node.elements) {
    if (element?.type !== 'Literal' || typeof element.value !== 'string') return undefined;
    strings.push(element.value);
  }
  return strings;
}

// Array source: a self-redefining function holding a string-array literal, or
// a top-level variable bound directly to one.
function findArraySources(ast) {
  const sources = [];
  walk(ast, node => {
    if (node.type === 'FunctionDeclaration' && node.id) {
      let strings;
      let reassigned = false;
      walk(node.body, inner => {
        if (inner !== node.body && isFunction(inner)) return false;
        if (inner.type === 'VariableDeclarator' && !strings) strings = stringArray(inner.init);
        if (inner.type === 'AssignmentExpression' && inner.left.type === 'Identifier' && inner.left.name === node.id.name) reassigned = true;
      });
      if (strings && reassigned) sources.push({ name: node.id.name, node, strings, form: 'function' });
    } else if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier') {
      const strings = stringArray(node.init);
      if (strings && strings.length >= 20) sources.push({ name: node.id.name, node, strings, form: 'variable' });
    }
  });
  return sources;
}

function referencesName(root, name) {
  let found = false;
  walk(root, node => {
    if (found) return false;
    if (node.type === 'Identifier' && node.name === name) found = true;
  });
  return found;
}

function decoderShape(fn, evaluator) {
  let offset;
  let alphabet;
  let has256 = false;
  const first = fn.params[0]?.type === 'Identifier' ? fn.params[0].name : undefined;
  if (!first) return undefined;
  walk(fn.body, node => {
    if (node.type === 'AssignmentExpression' && node.left.type === 'Identifier' && node.left.name === first) {
      let amount;
      if (node.operator === '-=') amount = node.right;
      else if (node.operator === '=' && node.right.type === 'BinaryExpression' && node.right.operator === '-' &&
        node.right.left.type === 'Identifier' && node.right.left.name === first) amount = node.right.right;
      if (amount) {
        const value = evaluator.evaluate(amount);
        if (typeof value === 'number' && Number.isInteger(value)) offset = value;
      }
    }
    if (node.type === 'Literal' && typeof node.value === 'string' && node.value.length === 65 &&
        /^[A-Za-z0-9+/=]+$/.test(node.value) && new Set(node.value).size === 65) alphabet = node.value;
    if (node.type === 'Literal' && node.value === 256) has256 = true;
  });
  // obfuscator.io decoders always rebase the index (`i = i - OFFSET`, even when
  // OFFSET is 0). Without it this is an ordinary lookup table, not a decoder.
  if (offset === undefined) return undefined;
  // Numeric constants are often split into expressions, so the RC4 S-box size
  // is a hint only; rotation solving confirms the variant.
  const second = fn.params[1]?.type === 'Identifier' ? fn.params[1].name : undefined;
  const keyUsed = second !== undefined && referencesName(fn.body, second);
  const variants = !alphabet ? ['plain'] : keyUsed ? (has256 ? ['rc4', 'base64'] : ['rc4', 'base64']) : ['base64'];
  return { offset, alphabet, variant: variants[0], variants };
}

function base64(text, alphabet) {
  const bytes = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of text) {
    const value = alphabet.indexOf(ch);
    if (value < 0 || value === 64) continue;
    buffer = ((buffer << 6) | value) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(bytes));
}

function rc4(text, key) {
  if (!key.length) return NO;
  const s = Array.from({ length: 256 }, (_, i) => i);
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + s[i] + key.charCodeAt(i % key.length)) % 256;
    [s[i], s[j]] = [s[j], s[i]];
  }
  let i = 0;
  j = 0;
  let out = '';
  for (let k = 0; k < text.length; k++) {
    i = (i + 1) % 256;
    j = (j + s[i]) % 256;
    [s[i], s[j]] = [s[j], s[i]];
    out += String.fromCharCode(text.charCodeAt(k) ^ s[(s[i] + s[j]) % 256]);
  }
  return out;
}

function makeDecoder(source, shape, rotation) {
  const { strings } = source;
  const cache = new Map();
  return args => {
    const index = args[0];
    if (typeof index !== 'number' || !Number.isInteger(index)) return NO;
    const position = index - shape.offset;
    if (position < 0 || position >= strings.length) return NO;
    const element = strings[(position + rotation.value) % strings.length];
    if (shape.variant === 'plain') return element;
    const key = shape.variant === 'rc4' ? args[1] : '';
    if (shape.variant === 'rc4' && typeof key !== 'string') return NO;
    const cacheKey = rotation.value + ':' + position + ':' + key;
    if (cache.has(cacheKey)) return cache.get(cacheKey);
    let value;
    try {
      const middle = base64(element, shape.alphabet);
      value = shape.variant === 'rc4' ? rc4(middle, key) : middle;
    } catch {
      value = NO;
    }
    if (cache.size < 50000) cache.set(cacheKey, value);
    return value;
  };
}

function propertyName(node) {
  if (node?.type !== 'MemberExpression') return undefined;
  if (!node.computed) return node.property.name;
  return node.property.type === 'Literal' ? String(node.property.value) : undefined;
}

function isRotation(node) {
  return node.type === 'CallExpression' && propertyName(node.callee) === 'push' &&
    node.arguments[0]?.type === 'CallExpression' && propertyName(node.arguments[0].callee) === 'shift';
}

function walkHas(root, test) {
  let hit = false;
  walk(root, node => {
    if (hit) return false;
    if (test(node)) hit = true;
  });
  return hit;
}

// Immediately invoked functions that rotate the array: they receive it as an
// argument or fetch it by name, and contain `x.push(x.shift())`.
function rotators(ast, source) {
  const found = [];
  walk(ast, node => {
    if (node.type !== 'CallExpression' || !isFunction(node.callee)) return;
    const passed = node.arguments.some(arg => arg.type === 'Identifier' && arg.name === source.name);
    if (!passed && !referencesName(node.callee.body, source.name)) return;
    // The rotation function is small; a module wrapper that merely contains a
    // push/shift somewhere is not one.
    let size = 0;
    let rotates = false;
    walk(node.callee.body, inner => {
      if (++size > 3000) return false;
      if (isRotation(inner)) rotates = true;
    });
    if (rotates && size <= 3000) found.push(node);
  });
  return found;
}

// The rotation loop's stopping condition: `if (v === target) break` with
// `const v = EXPR` in the same try block, or `if (TARGET == EXPR) break`.
function findChecksum(call) {
  const fn = call.callee;
  let found;
  walk(fn.body, node => {
    if (found || node.type !== 'TryStatement') return;
    const statements = node.block.body;
    const declared = name => {
      for (const other of statements) {
        if (other.type !== 'VariableDeclaration') continue;
        for (const declaration of other.declarations) {
          if (declaration.id.type === 'Identifier' && declaration.id.name === name && declaration.init) return declaration.init;
        }
      }
      return undefined;
    };
    for (const statement of statements) {
      if (statement.type !== 'IfStatement' || statement.test.type !== 'BinaryExpression' ||
          !['===', '=='].includes(statement.test.operator)) continue;
      const breaks = statement.consequent.type === 'BreakStatement' ||
        (statement.consequent.type === 'BlockStatement' && statement.consequent.body[0]?.type === 'BreakStatement');
      if (!breaks) continue;
      const { left, right } = statement.test;
      let expression;
      let target;
      if (left.type === 'Identifier' && declared(left.name)) { expression = declared(left.name); target = right; }
      else if (right.type === 'Identifier' && declared(right.name)) { expression = declared(right.name); target = left; }
      else if (walkHas(right, n => n.type === 'CallExpression')) { expression = right; target = left; }
      else if (walkHas(left, n => n.type === 'CallExpression')) { expression = left; target = right; }
      if (expression) { found = { call, fn, expression, target }; return; }
    }
  });
  return found;
}

export function deobfuscate(ast, scopes, order) {
  const sources = findArraySources(ast);
  const results = [];
  const resolved = new Map();
  if (!sources.length) return { arrays: results, resolved };
  const decoders = new Map();
  const arraySources = new Map();
  const shapeEvaluator = new Evaluator(scopes);
  const plans = [];
  const byName = new Map(sources.map(source => [source.name, source]));
  // One pass: the innermost function around each reference to an array source.
  const candidates = new Map();
  for (const node of order ?? []) {
    if (node.type !== 'Identifier' || !byName.has(node.name)) continue;
    const fn = scopes.owner(node);
    if (!fn || fn.type === 'Program') continue;
    const source = byName.get(node.name);
    if (fn === source.node || candidates.has(fn)) continue;
    const binding = scopes.lookup(node.name, node);
    const declared = source.node.type === 'VariableDeclarator' ? source.node.init : source.node;
    if (binding?.node !== declared && binding?.node !== source.node) continue;
    candidates.set(fn, source);
  }
  for (const source of sources) {
    arraySources.set(source.node.type === 'VariableDeclarator' ? source.node.init : source.node, new ArraySource(source.name));
  }
  // One rotation per array: several decoders (for example base64 and RC4) can
  // share an array and are rotated together.
  const rotations = new Map(sources.map(source => [source, { value: 0 }]));
  for (const [node, source] of candidates) {
    if (node.params.length < 1 || node.params.length > 3) continue;
    const parent = scopes.parent(node);
    if (parent?.type === 'CallExpression' && parent.callee === node) continue; // rotation IIFE
    // A decoder indexes the array; wrappers do not.
    let indexes = false;
    walk(node.body, inner => {
      if (indexes) return false;
      if (inner.type === 'MemberExpression' && inner.computed) indexes = true;
    });
    if (!indexes) continue;
    const shape = decoderShape(node, shapeEvaluator);
    if (!shape) continue;
    const rotation = rotations.get(source);
    decoders.set(node, makeDecoder(source, shape, rotation));
    plans.push({ source, decoder: node, shape, rotation });
  }
  if (!plans.length) return { arrays: results, resolved };
  const evaluator = new Evaluator(scopes, { decoders, arraySources });

  // Resolve a binding to a function, following `const alias = decoder`.
  const functionOf = (binding, depth = 0) => {
    if (binding?.kind === 'function') return binding.node;
    if (binding?.kind === 'value' && binding.node.type === 'Identifier' && depth < 4) {
      return functionOf(scopes.lookup(binding.node.name, binding.node), depth + 1);
    }
    return undefined;
  };
  // Call sites: calls whose callee is a decoder, or a helper that reaches one.
  const reaches = new Map();
  const reachedDecoder = (fn, depth = 0) => {
    if (decoders.has(fn)) return fn;
    if (reaches.has(fn)) return reaches.get(fn);
    reaches.set(fn, undefined);
    let result;
    if (depth < 8) {
      let body = fn.body;
      if (body?.type === 'BlockStatement' && body.body.length === 1 && body.body[0].type === 'ReturnStatement') body = body.body[0].argument;
      if (body?.type === 'CallExpression' && body.callee.type === 'Identifier') {
        const target = functionOf(scopes.lookup(body.callee.name, body.callee));
        if (target) result = reachedDecoder(target, depth + 1);
      }
    }
    reaches.set(fn, result);
    return result;
  };
  const sourceOf = new Map(plans.map(plan => [plan.decoder, plan.source]));
  const sites = [];
  walk(ast, node => {
    if (sites.length >= MAX_SITES) return false;
    if (node.type === 'CallExpression' && node.callee.type === 'Identifier') {
      const target = functionOf(scopes.lookup(node.callee.name, node.callee));
      const decoder = target && reachedDecoder(target);
      if (!decoder) return;
      // Calls inside wrappers are decoder plumbing, not call sites.
      const owner = scopes.owner(node);
      if (owner && owner.type !== 'Program' && reachedDecoder(owner)) return;
      sites.push({ node, source: sourceOf.get(decoder) });
    }
  });

  for (const source of sources) {
    const group = plans.filter(plan => plan.source === source);
    if (!group.length) continue;
    const rotation = rotations.get(source);
    const own = sites.filter(site => site.source === source).map(site => site.node);
    const n = source.strings.length;
    let method;
    const rotating = rotators(ast, source);
    const checksum = rotating.length === 1 ? findChecksum(rotating[0]) : undefined;
    if (checksum) {
      // Bind the loop's parameters to its call arguments.
      const frame = new Map();
      checksum.fn.params.forEach((param, i) => {
        const arg = checksum.call.arguments[i];
        if (param.type !== 'Identifier' || !arg) return;
        frame.set(param.name, arg.type === 'Identifier' && arg.name === source.name ? new ArraySource(source.name) : evaluator.evaluate(arg));
      });
      const frames = new Map([[checksum.fn, frame]]);
      const target = evaluator.evaluate(checksum.target, frames);
      if (typeof target === 'number') {
        // Every combination of candidate variants across this array's decoders.
        let combos = [[]];
        for (const plan of group) combos = combos.flatMap(combo => plan.shape.variants.map(v => [...combo, v]));
        for (const combo of combos.slice(0, 16)) {
          group.forEach((plan, i) => { plan.shape.variant = combo[i]; });
          for (let r = 0; r < n && !method; r++) {
            rotation.value = r;
            evaluator.memo.clear();
            if (evaluator.evaluate(checksum.expression, frames) === target) method = 'checksum';
          }
          if (method) break;
        }
        if (!method) for (const plan of group) plan.shape.variant = plan.shape.variants[0];
      }
    }
    const rotator = rotating.length > 0;
    if (!method && !rotator) {
      // No code rotates this array, so its stored order is the decoded order.
      rotation.value = 0;
      method = 'unrotated';
    }
    if (!method) {
      // Rotation is global, so require consensus across many call sites.
      const sample = own.slice(0, Math.max(8, Math.min(64, Math.floor(MAX_ROTATION_WORK / n))));
      let best = { r: -1, count: 0 };
      let second = 0;
      for (let r = 0; r < n && sample.length; r++) {
        rotation.value = r;
        evaluator.memo.clear();
        let count = 0;
        for (const site of sample) {
          const value = evaluator.evaluate(site);
          if (typeof value === 'string' && PRINTABLE.test(value)) count++;
        }
        if (count > best.count) { second = best.count; best = { r, count }; }
        else if (count > second) second = count;
      }
      if (best.r >= 0 && best.count >= Math.max(3, 0.8 * sample.length) && second <= 0.5 * best.count) {
        rotation.value = best.r;
        method = 'printable-consensus';
      }
    }
    if (!method) {
      rotation.value = -1;
      for (const plan of group) decoders.set(plan.decoder, () => NO);
    }
    // An array without rotation code, checksum or call sites is ordinary data.
    if (method === 'unrotated' && !own.length) continue;
    // A plain array variable (rather than obfuscator.io's self-redefining
    // function) is reported only when its rotation was proven; lookup tables
    // with index arithmetic otherwise look like decoders.
    if (source.form === 'variable' && method !== 'checksum' && method !== 'printable-consensus') continue;
    results.push({
      array: source.name, node: source.node, strings: n,
      variant: [...new Set(group.map(plan => plan.shape.variant))].join('+'),
      offset: group[0].shape.offset,
      rotation: method ? rotation.value : null, method: method ?? 'unresolved',
      source, sites: own,
    });
  }

  evaluator.memo.clear();
  for (const site of sites) {
    const value = evaluator.evaluate(site.node);
    if (typeof value === 'string') resolved.set(site.node, value);
  }
  for (const result of results) {
    result.callSites = result.sites.length;
    result.decodedSites = result.sites.filter(site => resolved.has(site)).length;
    delete result.sites;
    delete result.source;
  }
  return { arrays: results, resolved, evaluator };
}

// Measure string recovery for one tool on obfuscated samples.
// Scoring is the same for every tool:
//   O = distinct strings in the original input: string literals, template text,
//       and identifier property names and object keys (the obfuscator hides
//       `a.slice` as `a[decoder(...)]`);
//   I = distinct strings in the obfuscated sample outside the obfuscator's string array
//       (the largest all-string array literal in the sample, or any array literal that
//       reproduces at least 80% of it);
//   T = O \ I, the strings the obfuscator hid;
//   R = strings the tool produced: strings outside that array in its output,
//       or, for unk-scanner, the values of decoded call sites;
//   recovered = T ∩ R; wrong = R \ (O ∪ I), excluding the obfuscator's checksum
//   tokens (digits followed by letters), which are not program strings, and
//   strings that are concatenations of strings in O ∪ I (deobfuscators fold
//   'a' + 'b'), so that a wrong string is one the source cannot account for.
// Site-level check (scanner only): set scoring cannot see a wrong rotation of a
// plain or base64 array, which maps call sites to other genuine strings. The
// obfuscator replaces each string occurrence in place, so the scanner's decoded
// call sites in source order must align with the original's sequence of string
// literals and property names; sites outside the longest common subsequence of
// the two sequences are counted as misplaced.
// Baseline deobfuscators may execute decoder code (webcrack uses isolated-vm);
// all samples are generated from benign inputs.
// Usage: node measure.mjs TOOL ID...   (each ID begins with its sample-set label)
import fs from 'node:fs';
import { parse } from 'acorn';

const [tool, ...ids] = process.argv.slice(2);
const manifests = {};
const TOKEN = /^\d+[a-zA-Z]+$/;

let stringArray = new Set();
const allStrings = node => node.type === 'ArrayExpression' && node.elements.length >= 5 &&
  node.elements.every(e => e?.type === 'Literal' && typeof e.value === 'string');
const isObfuscatorArray = node => {
  if (!allStrings(node) || !stringArray.size || node.elements.length < 0.8 * stringArray.size) return false;
  return node.elements.filter(e => stringArray.has(e.value)).length >= 0.8 * node.elements.length;
};

function largestStringArray(code) {
  const ast = parse(code, { ecmaVersion: 'latest', sourceType: 'script', allowHashBang: true, allowReturnOutsideFunction: true });
  let best = [];
  const pending = [ast];
  while (pending.length) {
    const node = pending.pop();
    if (allStrings(node) && node.elements.length > best.length) best = node.elements.map(e => e.value);
    for (const key in node) {
      const value = node[key];
      if (Array.isArray(value)) { for (const child of value) if (child?.type) pending.push(child); }
      else if (value?.type) pending.push(value);
    }
  }
  return new Set(best);
}

function literals(code, skipArray = true) {
  const ast = parse(code, { ecmaVersion: 'latest', sourceType: 'script', allowHashBang: true, allowReturnOutsideFunction: true });
  const out = new Set();
  const pending = [ast];
  while (pending.length) {
    const node = pending.pop();
    if (skipArray && isObfuscatorArray(node)) continue;
    if (node.type === 'Literal' && typeof node.value === 'string') out.add(node.value);
    if (node.type === 'TemplateElement' && node.value.cooked != null) out.add(node.value.cooked);
    if (node.type === 'MemberExpression' && !node.computed && node.property.type === 'Identifier') out.add(node.property.name);
    if ((node.type === 'Property' || node.type === 'MethodDefinition') && !node.computed && node.key.type === 'Identifier') out.add(node.key.name);
    for (const key in node) {
      const value = node[key];
      if (Array.isArray(value)) { for (const child of value) if (child?.type) pending.push(child); }
      else if (value?.type) pending.push(value);
    }
  }
  return out;
}

function sequence(code) {
  const ast = parse(code, { ecmaVersion: 'latest', sourceType: 'script', allowHashBang: true, allowReturnOutsideFunction: true });
  const items = [];
  const pending = [ast];
  while (pending.length) {
    const node = pending.pop();
    if (node.type === 'ExpressionStatement' && node.directive) continue;
    if (node.type === 'Property' && !node.computed) { pending.push(node.value); continue; }
    if (node.type === 'Literal' && typeof node.value === 'string') items.push([node.start, node.value]);
    if (node.type === 'MemberExpression' && !node.computed && node.property.type === 'Identifier') items.push([node.property.start, node.property.name]);
    // The obfuscator also hides template-literal text and class method names.
    if (node.type === 'TemplateElement' && node.value.cooked) items.push([node.start, node.value.cooked]);
    if (node.type === 'MethodDefinition' && !node.computed && node.key.type === 'Identifier') items.push([node.key.start, node.key.name]);
    for (const key in node) {
      const value = node[key];
      if (Array.isArray(value)) { for (const child of value) if (child?.type) pending.push(child); }
      else if (value?.type) pending.push(value);
    }
  }
  return items.sort((a, b) => a[0] - b[0]).map(item => item[1]);
}

function lcs(a, b) {
  let previous = new Uint16Array(b.length + 1);
  let current = new Uint16Array(b.length + 1);
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      current[j] = a[i - 1] === b[j - 1] ? previous[j - 1] + 1 : Math.max(previous[j], current[j - 1]);
    }
    [previous, current] = [current, previous];
  }
  return previous[b.length];
}

async function scanner(engine, obfuscated) {
  const root = `${process.env.HOME}/${engine}/packages/unk-scanner/src/`;
  const ev = await import(root + 'evaluate.mjs');
  const { deobfuscate } = await import(root + 'deobfuscate.mjs');
  const ast = parse(obfuscated, { ecmaVersion: 'latest', sourceType: 'module' });
  const order = [];
  const pending = [ast];
  while (pending.length) {
    const node = pending.pop();
    order.push(node);
    for (const key in node) {
      const value = node[key];
      if (Array.isArray(value)) {
        for (let i = value.length - 1; i >= 0; i--) if (value[i]?.type) { value[i][ev.PARENT] = node; pending.push(value[i]); }
      } else if (value?.type && key !== 'loc') { value[ev.PARENT] = node; pending.push(value); }
    }
  }
  const scopes = ev.assignmentTargets ? new ev.Scopes(ev.assignmentTargets(order)) : new ev.Scopes();
  return deobfuscate(ast, scopes, order);
}

for (const id of ids) {
  const label = id.split('-')[0];
  manifests[label] ??= new Map(JSON.parse(fs.readFileSync(`samples-${label}.json`)).samples.map(s => [s.id, s]));
  const sample = manifests[label].get(id);
  const original = fs.readFileSync(`inputs/${sample.input}.js`, 'utf8');
  const obfuscated = fs.readFileSync(`samples/${label}/${id}.js`, 'utf8');
  stringArray = largestStringArray(obfuscated);
  const O = literals(original, false);
  const I = literals(obfuscated);
  const T = [...O].filter(s => !I.has(s));
  const started = performance.now();
  let R;
  const extra = {};
  try {
    if (tool === 'scanner-frozen' || tool === 'scanner-hardened') {
      const { arrays, resolved } = await scanner(tool === 'scanner-frozen' ? 'unk-bench' : 'unk-bench-mit', obfuscated);
      const values = [...resolved.values()].filter(v => !(TOKEN.test(v) && !O.has(v)));
      R = new Set(values);
      extra.arrays = arrays.map(a => ({ method: a.method, variant: a.variant, rotation: a.rotation, callSites: a.callSites, decodedSites: a.decodedSites }));
      extra.sites = values.length;
      extra.wrongSites = values.filter(v => !O.has(v) && !I.has(v)).length;
      const decodedInOrder = [...resolved].sort((a, b) => a[0].start - b[0].start).map(([, v]) => v)
        .filter(v => !(TOKEN.test(v) && !O.has(v)));
      const aligned = decodedInOrder.length ? lcs(decodedInOrder, sequence(original)) : 0;
      extra.misplacedSites = decodedInOrder.length - aligned;
    } else {
      let code;
      if (tool === 'synchrony') {
        const { Deobfuscator } = await import('deobfuscator');
        code = await new Deobfuscator().deobfuscateSource(obfuscated);
      } else if (tool === 'webcrack') {
        const { webcrack } = await import('webcrack');
        code = (await webcrack(obfuscated)).code;
      } else if (tool === 'obfuscator-io-deobfuscator') {
        const { deobfuscate } = await import('obfuscator-io-deobfuscator');
        code = deobfuscate(obfuscated);
      } else throw new Error('unknown tool');
      R = new Set([...literals(code)].filter(v => !(TOKEN.test(v) && !O.has(v))));
    }
    const recovered = T.filter(s => R.has(s)).length;
    const known = new Set([...O, ...I].filter(Boolean));
    const composed = text => {
      if (text.length > 4000) return false;
      const reach = new Uint8Array(text.length + 1);
      reach[0] = 1;
      for (let i = 0; i < text.length; i++) {
        if (!reach[i]) continue;
        for (const piece of known) if (text.startsWith(piece, i)) reach[i + piece.length] = 1;
      }
      return reach[text.length] === 1;
    };
    const wrong = [...R].filter(s => !O.has(s) && !I.has(s) && !composed(s));
    console.log(JSON.stringify({ tool, id, hidden: T.length, recovered, wrong: wrong.length,
      wrongExamples: wrong.slice(0, 3).map(w => w.slice(0, 40)),
      missedExamples: T.filter(s => !R.has(s)).slice(0, 3).map(w => w.slice(0, 40)), ms: Math.round(performance.now() - started), ...extra }));
  } catch (error) {
    console.log(JSON.stringify({ tool, id, hidden: T.length, error: String(error?.message ?? error).slice(0, 160),
      ms: Math.round(performance.now() - started) }));
  }
}

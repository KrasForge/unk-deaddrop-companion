// Validate the site-alignment check: on unencoded samples (whose string array
// holds the original strings), decode with the hardened scanner, then simulate a
// rotation error by moving every decoded value one array position on. The check
// must report almost all sites as misplaced for the simulated error and none for
// the actual decoding.
import fs from 'node:fs';
import { parse } from 'acorn';

const root = `${process.env.HOME}/unk-bench-mit/packages/unk-scanner/src/`;
const ev = await import(root + 'evaluate.mjs');
const { deobfuscate } = await import(root + 'deobfuscate.mjs');
const TOKEN = /^\d+[a-zA-Z]+$/;

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
    for (let j = 1; j <= b.length; j++) current[j] = a[i - 1] === b[j - 1] ? previous[j - 1] + 1 : Math.max(previous[j], current[j - 1]);
    [previous, current] = [current, previous];
  }
  return previous[b.length];
}

const samples = JSON.parse(fs.readFileSync('samples-v5.json')).samples
  .filter(s => s.encoding === 'none' && s.rotate && s.wrappers === 'none' && !s.callsTransform).slice(0, 25);
for (const sample of samples) {
  const code = fs.readFileSync(`samples/v5/${sample.id}.js`, 'utf8');
  const ast = parse(code, { ecmaVersion: 'latest', sourceType: 'module' });
  const order = [];
  const pending = [ast];
  while (pending.length) {
    const node = pending.pop();
    order.push(node);
    for (const key in node) {
      const value = node[key];
      if (Array.isArray(value)) { for (let i = value.length - 1; i >= 0; i--) if (value[i]?.type) { value[i][ev.PARENT] = node; pending.push(value[i]); } }
      else if (value?.type && key !== 'loc') { value[ev.PARENT] = node; pending.push(value); }
    }
  }
  const { resolved } = deobfuscate(ast, new ev.Scopes(ev.assignmentTargets(order)), order);
  let array = [];
  for (const node of order) if (node.type === 'ArrayExpression' && node.elements.length > array.length &&
    node.elements.every(e => e?.type === 'Literal' && typeof e.value === 'string')) array = node.elements.map(e => e.value);
  const decoded = [...resolved].sort((a, b) => a[0].start - b[0].start).map(([, v]) => v).filter(v => !TOKEN.test(v));
  const shifted = decoded.map(v => array[(array.indexOf(v) + 1) % array.length]).filter(v => !TOKEN.test(v));
  const truth = sequence(fs.readFileSync(`inputs/${sample.input}.js`, 'utf8'));
  console.log(sample.id, decoded.length, decoded.length - lcs(decoded, truth), shifted.length, shifted.length - lcs(shifted, truth));
}

// For one sample: the decoded call sites (revised engine, source order) that fall
// outside the longest common subsequence with the original's string sequence,
// with their neighbours, to tell alignment artifacts from decoding errors.
// Usage: node show-misplaced.mjs ID
import fs from 'node:fs';
import { parse } from 'acorn';

const id = process.argv[2];
const label = id.split('-')[0];
const sample = JSON.parse(fs.readFileSync(`samples-${label}.json`)).samples.find(s => s.id === id);
const root = `${process.env.HOME}/unk-bench-v2/packages/unk-scanner/src/`;
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
    if (node.type === 'TemplateElement' && node.value.cooked) items.push([node.start, node.value.cooked]);
    if ((node.type === 'MethodDefinition' || node.type === 'PropertyDefinition') && !node.computed && node.key.type === 'Identifier') items.push([node.key.start, node.key.name]);
    for (const key in node) {
      const value = node[key];
      if (Array.isArray(value)) { for (const child of value) if (child?.type) pending.push(child); }
      else if (value?.type) pending.push(value);
    }
  }
  return items.sort((a, b) => a[0] - b[0]).map(item => item[1]);
}

const code = fs.readFileSync(`samples/${label}/${id}.js`, 'utf8');
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
const a = [...resolved].sort((x, y) => x[0].start - y[0].start).map(([, v]) => v).filter(v => !TOKEN.test(v));
const b = sequence(fs.readFileSync(`inputs/${sample.input}.js`, 'utf8'));
// LCS table with backtracking (sequences are small).
const dp = Array.from({ length: a.length + 1 }, () => new Uint16Array(b.length + 1));
for (let i = a.length - 1; i >= 0; i--) for (let j = b.length - 1; j >= 0; j--) dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
let i = 0, j = 0;
while (i < a.length && j < b.length) {
  if (a[i] === b[j]) { i++; j++; }
  else if (dp[i + 1][j] >= dp[i][j + 1]) {
    console.log(JSON.stringify({ unmatched: a[i], before: a.slice(Math.max(0, i - 3), i), after: a.slice(i + 1, i + 4), inOriginal: b.includes(a[i]), originalAround: b.slice(Math.max(0, j - 3), j + 4) }));
    i++;
  } else j++;
}
while (i < a.length) console.log(JSON.stringify({ unmatched: a[i++], trailing: true }));

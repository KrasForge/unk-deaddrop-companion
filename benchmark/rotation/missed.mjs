// For one sample and one baseline tool: the hidden strings the tool's output
// lacks, and whether each survives inside a longer output string (folding).
import fs from 'node:fs';
import { parse } from 'acorn';

const [tool, id] = process.argv.slice(2);
const label = id.split('-')[0];
const sample = JSON.parse(fs.readFileSync(`samples-${label}.json`)).samples.find(s => s.id === id);
const original = fs.readFileSync(`inputs/${sample.input}.js`, 'utf8');
const obfuscated = fs.readFileSync(`samples/${label}/${id}.js`, 'utf8');

function strings(code) {
  const out = new Set();
  const pending = [parse(code, { ecmaVersion: 'latest', sourceType: 'script', allowHashBang: true, allowReturnOutsideFunction: true })];
  while (pending.length) {
    const node = pending.pop();
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

let code;
if (tool === 'webcrack') code = (await (await import('webcrack')).webcrack(obfuscated)).code;
else if (tool === 'synchrony') code = await new (await import('deobfuscator')).Deobfuscator().deobfuscateSource(obfuscated);
else code = (await import('obfuscator-io-deobfuscator')).deobfuscate(obfuscated);
const O = strings(original);
const I = strings(obfuscated);
const R = strings(code);
const joined = [...R].join('\u0000');
const missed = [...O].filter(s => !I.has(s) && !R.has(s));
console.log(JSON.stringify({ id, tool, missed: missed.length, folded: missed.filter(s => joined.includes(s)).length,
  examples: missed.slice(0, 6).map(s => s.slice(0, 40)) }));

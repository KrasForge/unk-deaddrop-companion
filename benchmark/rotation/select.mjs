// Select benign inputs for the controlled rotation experiment: calibration-corpus
// files with no findings, parsed by Acorn as scripts, 3-30 KB, at least 15 distinct
// string literals, one per package, seeded sample. Nothing is executed.
import fs from "node:fs";
import { parse } from "acorn";
const corpus = process.env.HOME + "/unk-bench/benchmark/private-corpus/";
const lines = fs.readFileSync(process.env.HOME + "/unk-bench/benchmark/results-4-cal-validated.jsonl", "utf8").split("\n");
const pool = new Map();
for (const line of lines) {
  if (!line) continue;
  const r = JSON.parse(line);
  if (r.status !== "parsed" || r.parser !== "acorn" || r.findings.length || r.deobfuscation?.length) continue;
  if (r.bytes < 3000 || r.bytes > 30000 || !/\.c?js$/.test(r.member) || /\.min\.js$/.test(r.member)) continue;
  if (!pool.has(r.package)) pool.set(r.package, r);
}
let seed = 20261030;
const rand = () => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648);
const candidates = [...pool.values()].sort((a, b) => a.sha256.localeCompare(b.sha256));
for (let i = candidates.length - 1; i > 0; i--) { const j = Math.floor(rand() * (i + 1)); [candidates[i], candidates[j]] = [candidates[j], candidates[i]]; }
const chosen = [];
for (const r of candidates) {
  if (chosen.length >= 50) break;
  const source = fs.readFileSync(corpus + r.sha256 + ".source", "utf8");
  let ast;
  try { ast = parse(source, { ecmaVersion: 2022, sourceType: "script", allowHashBang: true }); } catch { continue; }
  const strings = new Set();
  JSON.stringify(ast, (k, v) => { if (v && v.type === "Literal" && typeof v.value === "string") strings.add(v.value); return typeof v === "bigint" ? null : v; });
  if (strings.size < 15) continue;
  fs.writeFileSync(`inputs/${r.sha256}.js`, source);
  chosen.push({ sha256: r.sha256, package: r.package, member: r.member, bytes: r.bytes, distinctStrings: strings.size });
}
fs.writeFileSync("inputs.json", JSON.stringify({ seed: 20261030, poolPackages: pool.size, chosen }, null, 1));
console.log(pool.size, chosen.length, chosen.reduce((n, c) => n + c.distinctStrings, 0));

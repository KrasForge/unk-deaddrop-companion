// Obfuscate each benign input under a grid of javascript-obfuscator string-array
// options. Only the string-array transforms are enabled, so every string the
// obfuscator hides has a known original. Nothing is executed.
// Usage: node generate.mjs LABEL OBFUSCATOR_PACKAGE_DIR [INPUTS_MANIFEST]
import fs from 'node:fs';
import { createRequire } from 'node:module';

const [label, packageDir, inputManifest = 'inputs.json'] = process.argv.slice(2);
const require = createRequire(`${packageDir}/`);
const JavaScriptObfuscator = require('javascript-obfuscator');
const version = require('javascript-obfuscator/package.json').version;
const inputs = JSON.parse(fs.readFileSync(inputManifest)).chosen;
const grid = [];
for (const encoding of ['none', 'base64', 'rc4'])
  for (const rotate of [true, false])
    for (const wrappers of ['none', 'variable', 'function'])
      for (const callsTransform of [false, true])
        for (const indexShift of [false, true])
          grid.push({ encoding, rotate, wrappers, callsTransform, indexShift });

fs.mkdirSync(`samples/${label}`, { recursive: true });
const samples = [];
let n = 0;
for (const [ci, c] of grid.entries()) {
  for (const input of inputs) {
    const source = fs.readFileSync(`inputs/${input.sha256}.js`, 'utf8');
    const seed = 1000 + n++;
    const options = {
      compact: true, seed, target: 'node', stringArray: true, stringArrayThreshold: 1,
      stringArrayRotate: c.rotate, stringArrayShuffle: true,
      stringArrayEncoding: c.encoding === 'none' ? [] : [c.encoding],
      stringArrayIndexShift: c.indexShift,
      stringArrayWrappersCount: c.wrappers === 'none' ? 0 : 2,
      stringArrayWrappersType: c.wrappers === 'function' ? 'function' : 'variable',
      stringArrayWrappersChainedCalls: true, stringArrayWrappersParametersMaxCount: 4,
      stringArrayCallsTransform: c.callsTransform, stringArrayCallsTransformThreshold: 1,
      splitStrings: false, controlFlowFlattening: false, deadCodeInjection: false, selfDefending: false,
      transformObjectKeys: false, unicodeEscapeSequence: false, renameGlobals: false, numbersToExpressions: false,
    };
    const id = `${label}-c${String(ci).padStart(2, '0')}-${input.sha256.slice(0, 12)}`;
    const record = { id, label, config: ci, ...c, input: input.sha256, seed };
    try {
      fs.writeFileSync(`samples/${label}/${id}.js`, JavaScriptObfuscator.obfuscate(source, options).getObfuscatedCode());
    } catch (error) {
      record.error = String(error.message).slice(0, 200);
    }
    samples.push(record);
  }
}
fs.writeFileSync(`samples-${label}.json`, JSON.stringify({ obfuscator: `javascript-obfuscator@${version}`, inputs: inputManifest, grid, samples }, null, 1));
console.log(label, version, grid.length, samples.length, samples.filter(s => s.error).length);

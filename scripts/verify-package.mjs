import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import assert from 'node:assert/strict';

const temp = mkdtempSync(join(tmpdir(), 'unk-package-'));
const packageVersion = JSON.parse(readFileSync(new URL('../packages/unk-scanner/package.json', import.meta.url), 'utf8')).version;
// npm supplies its CLI path on all platforms; avoid a Windows shell command.
const npm = (...args) => execFileSync(process.execPath, [process.env.npm_execpath, ...args], {
  encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
});
try {
  const [pack] = JSON.parse(npm('pack', '--workspace', 'unk-scanner', '--pack-destination', temp, '--json'));
  assert.deepEqual(pack.files.map(f => f.path).sort(), [
    'LICENSE', 'README.md', 'bin/unk-scanner.mjs', 'package.json',
    'src/artifacts.mjs', 'src/bounded.mjs', 'src/cli.mjs', 'src/inspect.mjs', 'src/loaders.mjs', 'src/worker.mjs',
  ]);
  npm('install', '--prefix', temp, '--ignore-scripts', '--no-audit', '--no-fund', join(temp, pack.filename));
  const bin = resolve(temp, 'node_modules/unk-scanner/bin/unk-scanner.mjs');
  assert.equal(execFileSync(process.execPath, [bin, '--version'], { encoding: 'utf8' }).trim(), packageVersion);
  const sample = join(temp, 'fixture.js');
  writeFileSync(sample, 'navigator.clipboard.writeText("inert"); (navigator?.clipboard).writeText("inert"); throw new Error("must not execute");');
  const output = JSON.parse(execFileSync(process.execPath, [bin, sample], { encoding: 'utf8' }));
  assert.equal(output.findings[0].kind, 'clipboard-write');
  assert.equal(output.findings.length, 2);
  execFileSync(process.execPath, ['--input-type=module', '-e',
    "import { inspect } from 'unk-scanner'; if (inspect('const ok=1').findings.length) process.exit(1);",
  ], { cwd: temp });
  console.log('Package allowlist, installed CLI, and public API passed.');
} finally {
  rmSync(temp, { recursive: true, force: true });
}

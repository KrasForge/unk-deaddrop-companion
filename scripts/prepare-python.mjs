import { cpSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const npmRoot = resolve(root, 'packages/unk-scanner');
const engine = resolve(root, 'packages/unk-scanner-python/src/unk_scanner/_engine');
const require = createRequire(resolve(npmRoot, 'package.json'));
const acorn = dirname(require.resolve('acorn/package.json'));
if (JSON.parse(readFileSync(resolve(acorn, 'package.json'), 'utf8')).version !== '8.17.0') {
  throw new Error('Unexpected Acorn version');
}
rmSync(engine, { recursive: true, force: true });
mkdirSync(engine, { recursive: true });
for (const item of ['bin', 'src', 'package.json', 'LICENSE']) {
  cpSync(resolve(npmRoot, item), resolve(engine, item), { recursive: true });
}
cpSync(acorn, resolve(engine, 'node_modules/acorn'), { recursive: true });
// @babel/parser (TypeScript/JSX fallback) and its runtime dependencies.
for (const name of ['@babel/parser', '@babel/types', '@babel/helper-string-parser', '@babel/helper-validator-identifier']) {
  const dir = dirname(require.resolve(`${name}/package.json`));
  cpSync(dir, resolve(engine, 'node_modules', name), { recursive: true });
}
console.log('Staged current scanner, pinned Acorn and @babel/parser with licenses for Python build.');

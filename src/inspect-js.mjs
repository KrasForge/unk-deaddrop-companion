#!/usr/bin/env node
export { inspect, literalString, MAX_BYTES } from '../packages/unk-scanner/src/inspect.mjs';
export { main } from '../packages/unk-scanner/src/cli.mjs';
import { main } from '../packages/unk-scanner/src/cli.mjs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).catch(error => {
    process.stderr.write('inspect-js: ' + error.message + '\n');
    process.exitCode = 2;
  });
}

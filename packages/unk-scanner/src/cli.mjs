import { open, readFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { createHash } from 'node:crypto';
import { MAX_BYTES } from './inspect.mjs';
import { inspectBounded } from './bounded.mjs';
import { gunzipSync } from 'node:zlib';
const { version } = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));

export async function main(args) {
  if (args.length === 1 && ['--help', '-h'].includes(args[0])) {
    process.stdout.write('Usage: unk-scanner [--gzip] [--] FILE.js\n       unk-scanner --help | --version\n\nStatic JavaScript triage; emits JSON. Findings are review leads.\nExit 0: analysis completed (with or without findings). Exit 2: error.\n');
    return;
  }
  if (args.length === 1 && ['--version', '-v'].includes(args[0])) {
    process.stdout.write(version + '\n');
    return;
  }
  const gzip = args[0] === '--gzip';
  if (gzip) args = args.slice(1);
  if (args[0] === '--') args = args.slice(1);
  else if (args[0]?.startsWith('-')) throw new Error('Unknown option: ' + args[0]);
  if (args.length !== 1) throw new Error('Usage: unk-scanner [--gzip] [--] FILE.js');
  const handle = await open(args[0], constants.O_RDONLY | constants.O_NONBLOCK);
  let bytes;
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error('Input must be a regular file');
    if (stat.size > MAX_BYTES) throw new Error('Input exceeds 8 MiB limit');
    // Read at most the limit plus one, including if the input grows after stat().
    const buffer = Buffer.alloc(MAX_BYTES + 1);
    let count = 0;
    while (count < buffer.length) {
      const read = await handle.read(buffer, count, buffer.length - count, null);
      if (!read.bytesRead) break;
      count += read.bytesRead;
    }
    if (count > MAX_BYTES) throw new Error('Input exceeds 8 MiB limit');
    bytes = buffer.subarray(0, count);
  } finally {
    await handle.close();
  }
  if (!gzip && bytes[0] === 0x1f && bytes[1] === 0x8b) {
    throw new Error('Gzip input detected; use --gzip to decode with an 8 MiB output limit');
  }
  const decoded = gzip ? gunzipSync(bytes, { maxOutputLength: MAX_BYTES }) : bytes;
  const source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(decoded);
  const result = await inspectBounded(source);
  if (gzip) {
    result.decoded = {
      encoding: 'gzip', bytes: decoded.length,
      sha256: createHash('sha256').update(decoded).digest('hex'),
    };
  }
  result.sha256 = createHash('sha256').update(bytes).digest('hex');
  result.bytes = bytes.length;
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

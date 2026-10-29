import { open, readFile, readdir, lstat } from 'node:fs/promises';
import { constants } from 'node:fs';
import { createHash } from 'node:crypto';
import { cpus } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { MAX_BYTES, SCHEMA_VERSION, builtinRules } from './inspect.mjs';
import { ScannerPool, isolationProfile } from './isolate.mjs';
import { toSarif } from './sarif.mjs';
const { version } = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));

const USAGE = `Usage: unk-scanner [options] [--] PATH...
       unk-scanner --help | --version

Static JavaScript triage. Files are parsed in isolated processes and never
executed. Directories are searched for .js, .mjs and .cjs files.

Options:
  --format json|sarif      Output format (default json)
  --fail-on LEVEL          Exit 1 if a finding is at least LEVEL: error, warning,
                           note or none (default none)
  --rule FILE              Load an additional rule module (repeatable)
  --include-node-modules   Also search node_modules directories
  --timeout MS             Per-file analysis deadline (default 10000)
  --jobs N                 Parallel analysis processes (default up to 4)
  --strict                 Exit 2 if any file could not be analysed
  --gzip                   Decode one gzip-compressed input (8 MiB output limit)

Exit 0: analysis completed. Exit 1: --fail-on threshold reached. Exit 2: error.
Findings are review leads, not verdicts.
`;
const LEVELS = { none: Infinity, error: 3, warning: 2, note: 1 };
const RANK = { error: 3, warning: 2, note: 1 };
const EXTENSIONS = /\.(?:js|mjs|cjs)$/i;
const MAX_FILES = 100000;

function parseArgs(args) {
  const options = { format: 'json', failOn: 'none', rules: [], includeNodeModules: false, timeout: 10000, jobs: Math.min(4, cpus().length || 1), strict: false, gzip: false, paths: [] };
  const value = (name, i) => {
    if (i >= args.length) throw new Error(`Missing value for ${name}`);
    return args[i];
  };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--') { options.paths.push(...args.slice(i + 1)); break; }
    if (!arg.startsWith('-') || arg === '-') { options.paths.push(arg); continue; }
    switch (arg) {
      case '--format': options.format = value(arg, ++i); break;
      case '--fail-on': options.failOn = value(arg, ++i); break;
      case '--rule': options.rules.push(resolve(value(arg, ++i))); break;
      case '--include-node-modules': options.includeNodeModules = true; break;
      case '--timeout': options.timeout = Number(value(arg, ++i)); break;
      case '--jobs': options.jobs = Number(value(arg, ++i)); break;
      case '--strict': options.strict = true; break;
      case '--gzip': options.gzip = true; break;
      default: throw new Error('Unknown option: ' + arg);
    }
  }
  if (!['json', 'sarif'].includes(options.format)) throw new Error('--format must be json or sarif');
  if (!(options.failOn in LEVELS)) throw new Error('--fail-on must be error, warning, note or none');
  if (!Number.isInteger(options.timeout) || options.timeout < 1 || options.timeout > 600000) throw new Error('--timeout must be an integer from 1 to 600000');
  if (!Number.isInteger(options.jobs) || options.jobs < 1 || options.jobs > 64) throw new Error('--jobs must be an integer from 1 to 64');
  if (!options.paths.length) throw new Error('Usage: unk-scanner [options] [--] PATH...');
  return options;
}

async function readBounded(path) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error('Input must be a regular file');
    if (stat.size > MAX_BYTES) throw new Error('Input exceeds 8 MiB limit');
    // Read at most the limit plus one, including if the input grows after stat().
    const buffer = Buffer.alloc(Math.min(MAX_BYTES + 1, stat.size + 1 || 1));
    let count = 0;
    while (count < buffer.length) {
      const read = await handle.read(buffer, count, buffer.length - count, null);
      if (!read.bytesRead) break;
      count += read.bytesRead;
    }
    if (count > stat.size) {
      // The file grew; read up to the limit to decide.
      const more = Buffer.alloc(MAX_BYTES + 1 - count);
      let extra = 0;
      while (extra < more.length) {
        const read = await handle.read(more, extra, more.length - extra, null);
        if (!read.bytesRead) break;
        extra += read.bytesRead;
      }
      const all = Buffer.concat([buffer.subarray(0, count), more.subarray(0, extra)]);
      if (all.length > MAX_BYTES) throw new Error('Input exceeds 8 MiB limit');
      return all;
    }
    return buffer.subarray(0, count);
  } finally {
    await handle.close();
  }
}

async function collect(paths, includeNodeModules) {
  const files = [];
  let directory = false;
  const visit = async (path, top) => {
    if (files.length >= MAX_FILES) throw new Error(`More than ${MAX_FILES} files; narrow the paths`);
    let stat;
    try { stat = await lstat(path); } catch (error) {
      if (top) { files.push({ path, error: error.code === 'ENOENT' ? 'No such file' : error.message }); return; }
      throw error;
    }
    if (stat.isDirectory()) {
      directory = true;
      const entries = await readdir(path, { withFileTypes: true });
      entries.sort((a, b) => a.name.localeCompare(b.name));
      for (const entry of entries) {
        if (entry.isSymbolicLink()) continue;
        if (entry.isDirectory()) {
          if (entry.name === '.git' || (!includeNodeModules && entry.name === 'node_modules')) continue;
          await visit(join(path, entry.name), false);
        } else if (entry.isFile() && EXTENSIONS.test(entry.name)) files.push({ path: join(path, entry.name) });
      }
    } else if (top) files.push({ path });
  };
  for (const path of paths) await visit(path, true);
  return { files, directory };
}

async function analyse(file, pool, gzip) {
  let bytes;
  try {
    bytes = await readBounded(file.path);
  } catch (error) {
    return { path: file.path, error: error.code === 'ENOENT' ? 'No such file' : error.message };
  }
  try {
    if (!gzip && bytes[0] === 0x1f && bytes[1] === 0x8b) {
      throw new Error('Gzip input detected; use --gzip to decode with an 8 MiB output limit');
    }
    const decoded = gzip ? gunzipSync(bytes, { maxOutputLength: MAX_BYTES }) : bytes;
    const source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(decoded);
    const result = await pool.scan(source);
    if (gzip) {
      result.decoded = { encoding: 'gzip', bytes: decoded.length, sha256: createHash('sha256').update(decoded).digest('hex') };
    }
    result.sha256 = createHash('sha256').update(bytes).digest('hex');
    result.bytes = bytes.length;
    return { path: file.path, result };
  } catch (error) {
    return { path: file.path, error: error.message };
  }
}

async function loadRuleMeta(files) {
  const rules = [];
  for (const file of files) {
    const module = await import(pathToFileURL(file).href);
    rules.push(...[].concat(module.rules ?? (module.rule ? [module.rule] : module.default) ?? []));
  }
  return rules;
}

export async function main(args) {
  if (args.length === 1 && ['--help', '-h'].includes(args[0])) {
    process.stdout.write(USAGE);
    return;
  }
  if (args.length === 1 && ['--version', '-v'].includes(args[0])) {
    process.stdout.write(version + '\n');
    return;
  }
  const options = parseArgs(args);
  const extraRules = await loadRuleMeta(options.rules);
  const { files, directory } = await collect(options.paths, options.includeNodeModules);
  if (options.gzip && (files.length !== 1 || directory)) throw new Error('--gzip accepts exactly one file');
  const single = files.length === 1 && !directory && options.format === 'json' && options.paths.length === 1;
  const pool = new ScannerPool({ size: Math.min(options.jobs, Math.max(1, files.length)), timeoutMs: options.timeout, ruleFiles: options.rules });
  let outcomes;
  try {
    outcomes = await Promise.all(files.map(file => file.error ? file : analyse(file, pool, options.gzip)));
  } finally {
    pool.close();
  }
  if (single) {
    if (outcomes[0].error) throw new Error(outcomes[0].error);
    process.stdout.write(`${JSON.stringify(outcomes[0].result, null, 2)}\n`);
  } else if (options.format === 'sarif') {
    const sarif = toSarif(outcomes, { rules: [...builtinRules, ...extraRules], version, isolation: isolationProfile() });
    process.stdout.write(`${JSON.stringify(sarif, null, 2)}\n`);
  } else {
    process.stdout.write(`${JSON.stringify({
      schemaVersion: SCHEMA_VERSION, tool: { name: 'unk-scanner', version }, isolation: isolationProfile(),
      files: outcomes.map(({ path, result, error }) => error ? { path, error } : { path, ...result }),
    }, null, 2)}\n`);
  }
  const errors = outcomes.filter(outcome => outcome.error);
  if (errors.length) {
    for (const { path, error } of errors) process.stderr.write(`unk-scanner: ${path}: ${error}\n`);
    if (options.strict || errors.length === outcomes.length) { process.exitCode = 2; return; }
  }
  const threshold = LEVELS[options.failOn];
  const worst = Math.max(0, ...outcomes.flatMap(outcome => outcome.result?.findings.map(f => RANK[f.severity]) ?? []));
  if (worst >= threshold) process.exitCode = 1;
}

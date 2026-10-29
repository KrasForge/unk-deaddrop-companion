// Process-level isolation for parsing untrusted input. Each analysis process
// runs under the Node permission model (no file writes, child processes,
// workers or native addons; reads limited to the scanner's own code), with a
// capped heap, an empty environment and lower priority. On Linux it is also
// placed in an empty network namespace and given rlimits when the system
// allows it. Per-file deadlines kill the process; a fresh one replaces it.
import { spawn, spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setPriority } from 'node:os';
import { realpathSync } from 'node:fs';

const here = dirname(fileURLToPath(import.meta.url));
// Real paths: the permission model compares resolved paths, and temporary or
// package directories are often reached through symlinks (macOS /var).
const packageRoot = realpathSync(resolve(here, '..'));
const require = createRequire(import.meta.url);
const acornRoot = realpathSync(dirname(require.resolve('acorn/package.json')));
// @babel/parser and its dependencies live in one scope directory.
const babelRoot = realpathSync(dirname(dirname(require.resolve('@babel/parser/package.json'))));
const MAX_RESPONSE = 64 * 1024 * 1024;

let probed;
function probe() {
  if (probed) return probed;
  const works = command => {
    try {
      return spawnSync(command[0], [...command.slice(1), 'true'], { stdio: 'ignore', timeout: 5000 }).status === 0;
    } catch {
      return false;
    }
  };
  let network = null;
  if (process.platform === 'linux') {
    if (works(['unshare', '--net', '--map-current-user'])) network = ['unshare', '--net', '--map-current-user'];
    else if (works(['unshare', '--net', '--map-root-user'])) network = ['unshare', '--net', '--map-root-user'];
  }
  const prlimit = process.platform === 'linux' && works(['prlimit', '--core=0']);
  probed = { network, prlimit };
  return probed;
}

export function isolationProfile({ heapMb = 512 } = {}) {
  const { network, prlimit } = probe();
  return {
    mode: 'child-process',
    permissionModel: true,
    networkNamespace: Boolean(network),
    rlimits: prlimit ? { cpuSeconds: 600, fileSizeBytes: 0, openFiles: 128, core: 0 } : null,
    heapMb,
    environment: process.platform === 'win32' ? 'SystemRoot only' : 'empty',
  };
}

function command({ heapMb, ruleFiles }) {
  const { network, prlimit } = probe();
  const node = [process.execPath,
    `--max-old-space-size=${heapMb}`, '--max-semi-space-size=16',
    '--disallow-code-generation-from-strings',
    '--permission', `--allow-fs-read=${packageRoot}`, `--allow-fs-read=${acornRoot}`, `--allow-fs-read=${babelRoot}`,
    ...ruleFiles.map(file => `--allow-fs-read=${file}`),
    resolve(packageRoot, 'src', 'child.mjs'), ...ruleFiles];
  const limits = prlimit ? ['prlimit', '--cpu=600', '--fsize=0', '--nofile=128', '--core=0', '--'] : [];
  return [...(network ?? []), ...limits, ...node];
}

export class ScannerPool {
  constructor({ size = 1, timeoutMs = 10000, heapMb = 512, ruleFiles = [] } = {}) {
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 600000) {
      throw new Error('Timeout must be an integer from 1 to 600000 ms');
    }
    this.options = { timeoutMs, heapMb, ruleFiles: ruleFiles.map(file => realpathSync(resolve(file))) };
    this.size = Math.max(1, size);
    this.idle = [];
    this.queue = [];
    this.workers = new Set();
    this.nextId = 1;
    this.closed = false;
  }

  scan(source, filename) {
    if (this.closed) return Promise.reject(new Error('Scanner pool closed'));
    return new Promise((resolve, reject) => {
      this.queue.push({ id: this.nextId++, source, filename, resolve, reject });
      this.#pump();
    });
  }

  close() {
    this.closed = true;
    for (const worker of this.workers) this.#kill(worker);
    for (const job of this.queue.splice(0)) job.reject(new Error('Scanner pool closed'));
  }

  #pump() {
    while (this.queue.length) {
      let worker = this.idle.pop();
      if (!worker) {
        if (this.workers.size >= this.size) return;
        worker = this.#spawn();
      }
      this.#dispatch(worker, this.queue.shift());
    }
  }

  #spawn() {
    const [file, ...args] = command(this.options);
    // Windows needs SystemRoot for basic process services; nothing else is passed.
    const env = process.platform === 'win32' && process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {};
    const child = spawn(file, args, { stdio: ['pipe', 'pipe', 'pipe'], env, windowsHide: true });
    const worker = { child, buffer: '', job: null, ready: false, stderr: '' };
    try { setPriority(child.pid, 10); } catch { /* priority is best effort */ }
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', chunk => this.#data(worker, chunk));
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', chunk => { if (worker.stderr.length < 4096) worker.stderr += chunk; });
    child.stdin.on('error', () => {});
    child.on('error', error => this.#exit(worker, `Analysis process failed to start: ${error.message}`));
    child.on('exit', (code, signal) => this.#exit(worker, `Analysis process exited without a result (${signal ?? `code ${code}`})${worker.stderr ? ': ' + worker.stderr.trim().split('\n').pop() : ''}`));
    this.workers.add(worker);
    return worker;
  }

  #dispatch(worker, job) {
    worker.job = job;
    job.timer = setTimeout(() => {
      this.#kill(worker);
      job.reject(Object.assign(new Error('Analysis timed out; no complete result'), { code: 'TIMEOUT' }));
      worker.job = null;
      if (!this.closed) this.#pump();
    }, this.options.timeoutMs);
    worker.child.stdin.write(JSON.stringify({ id: job.id, source: job.source, filename: job.filename }) + '\n');
  }

  #data(worker, chunk) {
    worker.buffer += chunk;
    if (worker.buffer.length > MAX_RESPONSE) {
      this.#kill(worker);
      this.#finish(worker, new Error('Analysis response exceeded size limit'));
      return;
    }
    let newline;
    while ((newline = worker.buffer.indexOf('\n')) >= 0) {
      const line = worker.buffer.slice(0, newline);
      worker.buffer = worker.buffer.slice(newline + 1);
      let message;
      try { message = JSON.parse(line); } catch { this.#kill(worker); this.#finish(worker, new Error('Invalid response from analysis process')); return; }
      if (message.ready) { worker.ready = true; continue; }
      if (!worker.job || message.id !== worker.job.id) continue;
      if (message.error) {
        const error = message.syntax ? new SyntaxError(message.error) : new Error(message.error);
        this.#finish(worker, error);
      } else this.#finish(worker, null, message.result);
    }
  }

  #finish(worker, error, result) {
    const job = worker.job;
    if (!job) return;
    clearTimeout(job.timer);
    worker.job = null;
    if (error) job.reject(error); else job.resolve(result);
    if (this.closed) return;
    if (this.workers.has(worker)) this.idle.push(worker);
    this.#pump();
  }

  #exit(worker, message) {
    if (!this.workers.delete(worker)) return;
    this.idle = this.idle.filter(item => item !== worker);
    if (worker.job) this.#finish(worker, new Error(message));
    if (!this.closed) this.#pump();
  }

  #kill(worker) {
    this.workers.delete(worker);
    this.idle = this.idle.filter(item => item !== worker);
    try { worker.child.kill('SIGKILL'); } catch { /* already gone */ }
  }
}

// One-shot convenience used by the CLI for a single file.
export async function inspectIsolated(source, options = {}) {
  const pool = new ScannerPool(options);
  try {
    return await pool.scan(source);
  } finally {
    pool.close();
  }
}

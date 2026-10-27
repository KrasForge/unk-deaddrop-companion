import { Worker } from 'node:worker_threads';

// A worker bounds CLI parser runtime and V8 heap use. It never imports the input.
export function inspectBounded(source, { timeoutMs = 10000 } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000) {
    return Promise.reject(new Error('Timeout must be an integer from 1 to 60000 ms'));
  }
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./worker.mjs', import.meta.url), {
      workerData: source,
      resourceLimits: { maxOldGenerationSizeMb: 256, maxYoungGenerationSizeMb: 32, stackSizeMb: 4 },
      execArgv: [],
    });
    let finished = false;
    const finish = (error, result) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      void worker.terminate();
      if (error) reject(error);
      else resolve(result);
    };
    const timer = setTimeout(() => finish(new Error('Analysis timed out; no complete result')), timeoutMs);
    worker.once('message', message => {
      if (message.error) finish(new Error(message.error));
      else finish(null, message.result);
    });
    worker.once('error', error => finish(new Error('Analysis worker failed: ' + error.message)));
    worker.once('exit', code => {
      if (!finished) finish(new Error('Analysis worker exited without a result (code ' + code + ')'));
    });
  });
}

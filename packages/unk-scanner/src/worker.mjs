import { parentPort, workerData } from 'node:worker_threads';
import { inspect } from './inspect.mjs';

try {
  parentPort.postMessage({ result: inspect(workerData) });
} catch (error) {
  parentPort.postMessage({ error: error.message });
}

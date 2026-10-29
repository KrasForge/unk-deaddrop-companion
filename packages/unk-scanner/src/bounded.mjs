// Compatibility wrapper: analysis now runs in an isolated child process.
import { inspectIsolated } from './isolate.mjs';

export function inspectBounded(source, { timeoutMs = 10000 } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000) {
    return Promise.reject(new Error('Timeout must be an integer from 1 to 60000 ms'));
  }
  return inspectIsolated(source, { timeoutMs });
}

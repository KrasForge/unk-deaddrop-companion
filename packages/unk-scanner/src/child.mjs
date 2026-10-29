// Analysis process. Started by isolate.mjs under the Node permission model; it
// reads newline-delimited JSON requests on stdin and answers on stdout.
import { inspect } from './inspect.mjs';
import { pathToFileURL } from 'node:url';

const rules = [];
for (const file of process.argv.slice(2)) {
  const module = await import(pathToFileURL(file).href);
  const exported = module.rules ?? (module.rule ? [module.rule] : module.default);
  for (const rule of [].concat(exported ?? [])) rules.push(rule);
}

let buffer = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => {
  buffer += chunk;
  let newline;
  while ((newline = buffer.indexOf('\n')) >= 0) {
    const line = buffer.slice(0, newline);
    buffer = buffer.slice(newline + 1);
    let request;
    try {
      request = JSON.parse(line);
      const result = inspect(request.source, { rules, filename: request.filename });
      process.stdout.write(JSON.stringify({ id: request.id, result }) + '\n');
    } catch (error) {
      process.stdout.write(JSON.stringify({
        id: request?.id, error: error?.message ?? String(error), syntax: error instanceof SyntaxError,
      }) + '\n');
    }
  }
});
process.stdin.on('end', () => process.exit(0));
process.stdout.write(JSON.stringify({ ready: true, rules: rules.length }) + '\n');

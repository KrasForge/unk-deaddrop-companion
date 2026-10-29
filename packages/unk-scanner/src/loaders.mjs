// Recognize an embedded encrypted payload whose decrypted text reaches a
// code-compiling sink. Bindings are followed through scopes (const, and
// let/var that are never reassigned); input is never evaluated. This
// establishes syntax relationships, not runtime behavior.
const SINKS = new Map([
  ['_compile', 0], ['runInThisContext', 0], ['runInNewContext', 0], ['runInContext', 0], ['compileFunction', 0],
]);
const CIPHER = /^(?:aes|chacha20|des|des-ede3|camellia|aria|sm4|bf|cast5|rc4)(?:[-\w]*)$/i;
const PAYLOAD_ENCODINGS = new Set(['base64', 'base64url', 'hex']);
const MIN_PAYLOAD = 8;

export function encryptedLoaders(ast, literalString, position, { scopes, order } = {}) {
  if (!scopes || !order) return [];
  const method = node => node?.type === 'MemberExpression'
    ? (node.computed ? literalString(node.property) : node.property.name) : undefined;
  const isCall = (node, name) => node?.type === 'CallExpression' && method(node.callee) === name;
  const global = (node, name) => node?.type === 'Identifier' && node.name === name && !scopes.lookup(name, node);

  // The expression a name stands for, when it has a single definition.
  const definition = node => {
    if (node?.type !== 'Identifier') return undefined;
    const binding = scopes.lookup(node.name, node);
    return binding?.kind === 'value' ? binding.node : undefined;
  };
  // Strip wrappers that keep the same bytes or text.
  const through = (node, depth = 0) => {
    for (let i = 0; node && i < 16 && depth < 24; i++) {
      const defined = definition(node);
      if (defined) { node = defined; continue; }
      if (node.type === 'AwaitExpression' || node.type === 'ParenthesizedExpression') { node = node.argument ?? node.expression; continue; }
      if (node.type === 'CallExpression' && ['toString', 'subarray', 'slice'].includes(method(node.callee))) { node = node.callee.object; continue; }
      break;
    }
    return node;
  };
  // An embedded payload: Buffer.from('<encoded literal>', enc), possibly sliced,
  // or a literal passed with its input encoding to update().
  const payload = (node, encoding) => {
    node = through(node);
    if (node?.type === 'CallExpression' && method(node.callee) === 'from' && global(node.callee.object, 'Buffer')) {
      const text = literalString(through(node.arguments[0]));
      if (text !== undefined && text.length >= MIN_PAYLOAD && PAYLOAD_ENCODINGS.has(literalString(node.arguments[1]))) return node;
    }
    const text = literalString(node);
    if (text !== undefined && text.length >= MIN_PAYLOAD && PAYLOAD_ENCODINGS.has(encoding)) return node;
    return undefined;
  };
  // A decipher object created with a recognised cipher name.
  const decipher = node => {
    const created = through(node);
    if (!isCall(created, 'createDecipheriv') && !isCall(created, 'createDecipher')) return undefined;
    const algorithm = literalString(created.arguments[0]);
    return algorithm && CIPHER.test(algorithm) ? created : undefined;
  };
  // Decrypted text: update()/final() of a decipher, joined by Buffer.concat or +.
  const decrypted = (node, depth = 0) => {
    node = through(node);
    if (!node || depth > 8) return undefined;
    if (node.type === 'BinaryExpression' && node.operator === '+') return decrypted(node.left, depth + 1) ?? decrypted(node.right, depth + 1);
    if (node.type === 'CallExpression' && method(node.callee) === 'concat' && global(node.callee.object, 'Buffer') &&
        node.arguments[0]?.type === 'ArrayExpression') {
      for (const part of node.arguments[0].elements) {
        const found = decrypted(part, depth + 1);
        if (found) return found;
      }
      return undefined;
    }
    if (isCall(node, 'update')) {
      const created = decipher(node.callee.object);
      const embedded = created && payload(node.arguments[0], literalString(node.arguments[1]));
      return embedded ? { created, embedded, update: node } : undefined;
    }
    return undefined;
  };
  const sinkArgument = node => {
    if (node.type === 'CallExpression') {
      const name = method(node.callee);
      if (SINKS.has(name)) return node.arguments[SINKS.get(name)];
      if (global(node.callee, 'eval')) return node.arguments[0];
      if (global(node.callee, 'Function')) return node.arguments.at(-1);
    }
    if (node.type === 'NewExpression') {
      if (method(node.callee) === 'Script' || global(node.callee, 'Script')) return node.arguments[0];
      if (global(node.callee, 'Function')) return node.arguments.at(-1);
    }
    return undefined;
  };

  const results = [];
  for (const node of order) {
    if (node.type !== 'CallExpression' && node.type !== 'NewExpression') continue;
    const argument = sinkArgument(node);
    if (!argument) continue;
    const found = decrypted(argument);
    if (!found) continue;
    const algorithm = literalString(found.created.arguments[0]).toLowerCase();
    // Authenticated modes are evidence when the tag is set on the same object.
    const tag = order.find(call => isCall(call, 'setAuthTag') && through(call.callee.object) === found.created);
    results.push({
      node,
      algorithm,
      evidence: [
        ['embedded-payload', found.embedded], ['cipher', found.created],
        ...(tag ? [['authentication-tag', tag]] : []), ['decrypted-text', found.update], ['code-sink', node],
      ].map(([role, at]) => ({ role, ...position(at.start) })),
    });
  }
  return results;
}

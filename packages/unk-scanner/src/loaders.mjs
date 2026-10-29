// Recognize a narrow top-level const-binding pattern. Names may vary; input is
// never evaluated. This establishes syntax relationships, not runtime behavior.
export function encryptedLoaders(ast, literalString, position) {
  const bindings = new Map();
  const calls = [];
  const method = node => node?.type === 'MemberExpression'
    ? (node.computed ? literalString(node.property) : node.property.name) : undefined;
  const id = node => node?.type === 'Identifier' ? node.name : undefined;
  const isCall = (node, name) => node?.type === 'CallExpression' && method(node.callee) === name;
  const binding = (node, before) => {
    const found = bindings.get(id(node));
    return found && found.start < before ? found.init : undefined;
  };
  const collect = expression => {
    if (expression?.type === 'SequenceExpression') expression.expressions.forEach(collect);
    else if (expression?.type === 'CallExpression') calls.push(expression);
  };
  for (const statement of ast.body) {
    if (statement.type === 'VariableDeclaration' && statement.kind === 'const') {
      for (const declaration of statement.declarations) {
        if (declaration.id.type === 'Identifier') bindings.set(declaration.id.name, declaration);
      }
    } else if (statement.type === 'ExpressionStatement') collect(statement.expression);
  }
  const slice = (node, before, start, end) => {
    const init = binding(node, before);
    if (!isCall(init, 'subarray')) return undefined;
    const args = init.arguments;
    if (args.length !== (end === undefined ? 1 : 2) ||
        args[0]?.type !== 'Literal' || args[0].value !== start ||
        (end !== undefined && (args[1]?.type !== 'Literal' || args[1].value !== end))) return undefined;
    return id(init.callee.object);
  };
  const results = [];
  for (const compile of calls) {
    if (!isCall(compile, '_compile')) continue;
    const source = binding(compile.arguments[0], compile.start);
    if (!isCall(source, 'toString') || !['utf8', 'utf-8'].includes(literalString(source.arguments[0]))) continue;
    const concat = source.callee.object;
    if (!isCall(concat, 'concat') || id(concat.callee.object) !== 'Buffer' ||
        concat.arguments.length !== 1 || concat.arguments[0].type !== 'ArrayExpression') continue;
    const parts = concat.arguments[0].elements;
    if (parts.length !== 2 || !isCall(parts[0], 'update') || !isCall(parts[1], 'final')) continue;
    const decipherName = id(parts[0].callee.object);
    if (!decipherName || id(parts[1].callee.object) !== decipherName) continue;
    const decipher = binding(parts[0].callee.object, source.start);
    if (!isCall(decipher, 'createDecipheriv') || literalString(decipher.arguments[0]) !== 'aes-256-gcm') continue;
    const payloadName = slice(decipher.arguments[2], decipher.start, 0, 12);
    if (!payloadName || slice(parts[0].arguments[0], source.start, 28) !== payloadName) continue;
    const payload = bindings.get(payloadName);
    if (!payload || payload.start >= decipher.start || !isCall(payload.init, 'from') ||
        id(payload.init.callee.object) !== 'Buffer' ||
        literalString(payload.init.arguments[1]) !== 'base64' ||
        literalString(payload.init.arguments[0]) === undefined) continue;
    const tag = calls.find(call => isCall(call, 'setAuthTag') &&
      id(call.callee.object) === decipherName && call.start > decipher.start && call.start < source.start &&
      slice(call.arguments[0], call.start, 12, 28) === payloadName);
    if (!tag) continue;
    results.push({
      node: compile,
      evidence: [
        ['embedded-base64', payload.init], ['aes-256-gcm', decipher],
        ['authentication-tag', tag], ['decoded-text', source], ['module-compile', compile],
      ].map(([role, node]) => ({ role, ...position(node.start) })),
    });
  }
  return results;
}

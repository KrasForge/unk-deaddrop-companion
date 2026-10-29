// Pure partial evaluation over the AST. Nothing from the input is executed:
// the evaluator interprets a small, side-effect-free expression subset
// (literals, arithmetic, string operations, constant bindings and
// single-return helper functions) and gives up on anything else.

export const NO = Symbol('unresolved');
const MAX_DEPTH = 48;
const MAX_STEPS = 20000;
const MAX_ARRAY = 10000;
const MAX_STRING = 1 << 20;
const FUNCTION_TYPES = new Set(['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']);
const STRING_METHODS = new Set(['slice', 'substring', 'substr', 'charAt', 'charCodeAt', 'toLowerCase',
  'toUpperCase', 'concat', 'trim', 'indexOf', 'startsWith', 'endsWith', 'includes', 'padStart', 'padEnd']);

export class FnRef { constructor(node) { this.node = node; } }
export class ObjRef { constructor(node) { this.node = node; } }
export class ArraySource { constructor(id) { this.id = id; } }

const primitive = value => value === null || ['string', 'number', 'boolean', 'undefined'].includes(typeof value);

export function isFunction(node) { return FUNCTION_TYPES.has(node?.type); }

// Lexical scopes are function-level; block-level `const` declarations are
// attributed to their function. Conflicting declarations become ambiguous.
export const PARENT = Symbol('parent');

export class Scopes {
  constructor() {
    this.cache = new Map();
  }

  parent(node) { return node[PARENT]; }

  owner(node) {
    for (let current = node[PARENT]; current; current = current[PARENT]) {
      if (isFunction(current) || current.type === 'Program') return current;
    }
    return undefined;
  }

  bindings(fn) {
    let map = this.cache.get(fn);
    if (map) return map;
    map = new Map();
    const set = (name, binding) => {
      const previous = map.get(name);
      map.set(name, previous ? { kind: 'ambiguous' } : binding);
    };
    if (fn.type !== 'Program') {
      for (const param of fn.params) if (param.type === 'Identifier') set(param.name, { kind: 'param', fn, name: param.name });
      if (fn.type === 'FunctionExpression' && fn.id) map.set(fn.id.name, { kind: 'function', node: fn });
    }
    const pending = fn.type === 'Program' ? [...fn.body] : [fn.body];
    while (pending.length) {
      const node = pending.pop();
      if (!node || typeof node.type !== 'string') continue;
      if (node.type === 'FunctionDeclaration') {
        if (node.id) set(node.id.name, { kind: 'function', node });
        continue;
      }
      if (isFunction(node) || node.type === 'ClassDeclaration' || node.type === 'ClassExpression') continue;
      if (node.type === 'VariableDeclaration') {
        for (const declaration of node.declarations) {
          if (declaration.id.type !== 'Identifier') continue;
          const init = declaration.init;
          if (isFunction(init)) set(declaration.id.name, { kind: 'function', node: init });
          else if (node.kind === 'const' && init?.type === 'ObjectExpression') set(declaration.id.name, { kind: 'object', node: init });
          else if (node.kind === 'const' && init) set(declaration.id.name, { kind: 'value', node: init });
          else set(declaration.id.name, { kind: 'opaque', init });
        }
      }
      for (const key in node) {
        if (key === 'type' || key === 'loc') continue;
        const value = node[key];
        if (Array.isArray(value)) { for (const child of value) if (child?.type) pending.push(child); }
        else if (value?.type) pending.push(value);
      }
    }
    this.cache.set(fn, map);
    return map;
  }

  lookup(name, at) {
    for (let fn = this.owner(at); fn; fn = fn.type === 'Program' ? undefined : this.owner(fn)) {
      const binding = this.bindings(fn).get(name);
      if (binding) return binding;
    }
    return undefined;
  }
}

export class Evaluator {
  constructor(scopes, { decoders = new Map(), arraySources = new Map() } = {}) {
    this.scopes = scopes;
    this.decoders = decoders;       // function node -> (values) => string | NO
    this.arraySources = arraySources; // function or declaration node -> ArraySource
    this.memo = new Map();
  }

  // Evaluate an expression; returns a JavaScript value or NO.
  evaluate(node, frames = null) {
    const state = { steps: 0 };
    try {
      return this.#eval(node, frames, 0, state);
    } catch (error) {
      if (error === NO) return NO;
      throw error;
    }
  }

  string(node, frames = null) {
    const value = this.evaluate(node, frames);
    return typeof value === 'string' ? value : undefined;
  }

  #fail() { throw NO; }

  #binding(name, at, frames) {
    const binding = this.scopes.lookup(name, at);
    if (!binding) return NO;
    switch (binding.kind) {
      case 'param': {
        const frame = frames?.get(binding.fn);
        return frame && frame.has(name) ? frame.get(name) : NO;
      }
      case 'function':
        return this.arraySources.get(binding.node) ?? new FnRef(binding.node);
      case 'object':
        return new ObjRef(binding.node);
      case 'value':
        return { deferred: binding.node };
      default:
        return NO;
    }
  }

  #eval(node, frames, depth, state) {
    if (!node || depth > MAX_DEPTH || ++state.steps > MAX_STEPS) this.#fail();
    switch (node.type) {
      case 'Literal':
        if (node.regex || typeof node.value === 'bigint') this.#fail();
        return node.value;
      case 'TemplateLiteral': {
        let out = node.quasis[0].value.cooked;
        if (out == null) this.#fail();
        for (let i = 0; i < node.expressions.length; i++) {
          const value = this.#eval(node.expressions[i], frames, depth + 1, state);
          if (!primitive(value)) this.#fail();
          out += String(value) + (node.quasis[i + 1].value.cooked ?? this.#fail());
        }
        return out;
      }
      case 'Identifier': {
        if (node.name === 'undefined' && !this.scopes.lookup('undefined', node)) return undefined;
        let value = this.#binding(node.name, node, frames);
        if (value === NO) this.#fail();
        if (value?.deferred) {
          const key = value.deferred;
          if (this.memo.has(key)) value = this.memo.get(key);
          else {
            this.memo.set(key, NO); // cycle guard
            try { value = this.#eval(key, frames, depth + 1, state); } catch (error) { if (error !== NO) throw error; value = NO; }
            // Only memoize frame-independent results.
            if (!frames) this.memo.set(key, value); else this.memo.delete(key);
          }
          if (value === NO) this.#fail();
        }
        return value;
      }
      case 'ChainExpression':
        return this.#eval(node.expression, frames, depth + 1, state);
      case 'ArrayExpression': {
        if (node.elements.length > MAX_ARRAY) this.#fail();
        return node.elements.map(element => {
          if (!element || element.type === 'SpreadElement') this.#fail();
          return this.#eval(element, frames, depth + 1, state);
        });
      }
      case 'UnaryExpression': {
        const value = this.#eval(node.argument, frames, depth + 1, state);
        switch (node.operator) {
          case '!': return !value;
          case 'void': return undefined;
          case '-': if (typeof value === 'number') return -value; break;
          case '+': if (typeof value === 'number' || typeof value === 'boolean') return +value; break;
          case '~': if (typeof value === 'number') return ~value; break;
          case 'typeof': if (primitive(value)) return value === null ? 'object' : typeof value; break;
        }
        return this.#fail();
      }
      case 'BinaryExpression': {
        const left = this.#eval(node.left, frames, depth + 1, state);
        const right = this.#eval(node.right, frames, depth + 1, state);
        if (!primitive(left) || !primitive(right)) this.#fail();
        const result = binary(node.operator, left, right);
        if (result === NO || (typeof result === 'string' && result.length > MAX_STRING)) this.#fail();
        return result;
      }
      case 'LogicalExpression': {
        const left = this.#eval(node.left, frames, depth + 1, state);
        if (node.operator === '&&') return left ? this.#eval(node.right, frames, depth + 1, state) : left;
        if (node.operator === '||') return left ? left : this.#eval(node.right, frames, depth + 1, state);
        return left ?? this.#eval(node.right, frames, depth + 1, state);
      }
      case 'ConditionalExpression':
        return this.#eval(this.#eval(node.test, frames, depth + 1, state) ? node.consequent : node.alternate,
          frames, depth + 1, state);
      case 'MemberExpression':
        return this.#member(node, frames, depth, state);
      case 'CallExpression':
        return this.#call(node, frames, depth, state);
      default:
        return this.#fail();
    }
  }

  #property(node, frames, depth, state) {
    if (!node.computed) return node.property.type === 'Identifier' ? node.property.name : this.#fail();
    const key = this.#eval(node.property, frames, depth + 1, state);
    if (typeof key !== 'string' && typeof key !== 'number') this.#fail();
    return String(key);
  }

  #objectValue(ref, key, frames, depth, state) {
    let found;
    for (const property of ref.node.properties) {
      if (property.type !== 'Property' || property.kind !== 'init') this.#fail();
      let name;
      if (!property.computed) name = property.key.type === 'Identifier' ? property.key.name : String(property.key.value);
      else name = String(this.#eval(property.key, null, depth + 1, state));
      if (name === key) found = property.value;
    }
    if (!found) this.#fail();
    if (isFunction(found)) return new FnRef(found);
    if (found.type === 'ObjectExpression') return new ObjRef(found);
    // Object values are evaluated in their defining scope, not the caller's frames.
    return this.#eval(found, null, depth + 1, state);
  }

  #member(node, frames, depth, state) {
    const object = this.#eval(node.object, frames, depth + 1, state);
    const key = this.#property(node, frames, depth, state);
    if (object instanceof ObjRef) return this.#objectValue(object, key, frames, depth, state);
    if (typeof object === 'string' || Array.isArray(object)) {
      if (key === 'length') return object.length;
      if (/^(0|[1-9]\d*)$/.test(key) && Number(key) < object.length) return object[Number(key)];
    }
    if (object instanceof ArraySource) this.#fail();
    return this.#fail();
  }

  #callee(node, frames, depth, state) {
    const callee = node.callee.type === 'ChainExpression' ? node.callee.expression : node.callee;
    if (callee.type === 'Identifier') {
      if ((callee.name === 'parseInt' || callee.name === 'String') && !this.scopes.lookup(callee.name, callee)) {
        return { builtin: callee.name };
      }
      return this.#eval(callee, frames, depth + 1, state);
    }
    if (callee.type === 'MemberExpression') {
      const objectNode = callee.object;
      if (objectNode.type === 'Identifier' && !this.scopes.lookup(objectNode.name, objectNode)) {
        const key = this.#property(callee, frames, depth, state);
        if (objectNode.name === 'String' && key === 'fromCharCode') return { builtin: 'fromCharCode' };
        if (objectNode.name === 'Number' && key === 'parseInt') return { builtin: 'parseInt' };
      }
      const object = this.#eval(objectNode, frames, depth + 1, state);
      const key = this.#property(callee, frames, depth, state);
      if (object instanceof ObjRef) return this.#objectValue(object, key, frames, depth, state);
      if (typeof object === 'string' && STRING_METHODS.has(key)) return { method: key, target: object };
      if (Array.isArray(object) && key === 'join') return { method: 'join', target: object };
    }
    return this.#fail();
  }

  #call(node, frames, depth, state) {
    const target = this.#callee(node, frames, depth, state);
    const args = node.arguments.map(arg => arg.type === 'SpreadElement'
      ? this.#fail() : this.#eval(arg, frames, depth + 1, state));
    if (target?.builtin) {
      if (!args.every(primitive)) this.#fail();
      if (target.builtin === 'parseInt') return Number.parseInt(String(args[0]), args[1]);
      if (target.builtin === 'String') return args.length ? String(args[0]) : '';
      if (target.builtin === 'fromCharCode') {
        if (!args.every(x => typeof x === 'number')) this.#fail();
        return String.fromCharCode(...args);
      }
    }
    if (target?.method) {
      if (!args.every(primitive)) this.#fail();
      if (target.method === 'join') {
        if (!target.target.every(primitive)) this.#fail();
        return target.target.join(args[0] === undefined ? ',' : String(args[0]));
      }
      const result = String.prototype[target.method].apply(target.target, args);
      if (typeof result === 'string' && result.length > MAX_STRING) this.#fail();
      return result;
    }
    if (target instanceof FnRef) {
      const decode = this.decoders.get(target.node);
      if (decode) {
        const value = decode(args);
        return value === NO ? this.#fail() : value;
      }
      return this.#inline(target.node, args, frames, depth, state);
    }
    return this.#fail();
  }

  // Inline a helper whose body is a single return of a supported expression.
  #inline(fn, args, frames, depth, state) {
    let body = fn.body;
    if (fn.async || fn.generator) this.#fail();
    if (body.type === 'BlockStatement') {
      if (body.body.length !== 1 || body.body[0].type !== 'ReturnStatement' || !body.body[0].argument) this.#fail();
      body = body.body[0].argument;
    }
    const frame = new Map();
    fn.params.forEach((param, index) => {
      if (param.type !== 'Identifier') this.#fail();
      frame.set(param.name, args[index]);
    });
    const next = new Map(frames ?? []);
    next.set(fn, frame);
    return this.#eval(body, next, depth + 1, state);
  }
}

function binary(operator, left, right) {
  switch (operator) {
    case '+': return left + right;
    case '-': return left - right;
    case '*': return left * right;
    case '/': return left / right;
    case '%': return left % right;
    case '**': return left ** right;
    case '|': return left | right;
    case '&': return left & right;
    case '^': return left ^ right;
    case '<<': return left << right;
    case '>>': return left >> right;
    case '>>>': return left >>> right;
    case '===': return left === right;
    case '!==': return left !== right;
    case '==': return left == right;
    case '!=': return left != right;
    case '<': return left < right;
    case '<=': return left <= right;
    case '>': return left > right;
    case '>=': return left >= right;
    default: return NO;
  }
}

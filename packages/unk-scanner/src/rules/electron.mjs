// Electron runtime boundary. Reading ELECTRON_RUN_AS_NODE is common (native
// addon loaders do it); launching a process with it set turns a signed editor
// binary into a general Node interpreter.

const CHILD_PROCESS = new Set(['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']);
const HIDDEN_SCRIPT = /(?:^|[\s"'=\\/])(?:\/tmp|\/var\/tmp|%TEMP%|%TMP%|\$TMPDIR|\$env:TEMP|AppData[\\/]Local[\\/]Temp|\.vscode)[\\/][^\s"']*\.(?:js|cjs|mjs|py|sh|ps1|vbs|bat|cmd)\b/i;

const SCRIPT_SET = /\$env:ELECTRON_RUN_AS_NODE\s*=\s*['"]?1|\b(?:set|export)\s+ELECTRON_RUN_AS_NODE=1|(?:^|[\s;&])ELECTRON_RUN_AS_NODE=1\s+\S/i;

function childProcessCall(context, node) {
  const name = context.memberName(node.callee) ??
    (node.callee.type === 'Identifier' ? node.callee.name : undefined);
  return name && CHILD_PROCESS.has(name) ? name : undefined;
}

// Legitimate language clients routinely launch helpers with
// ELECTRON_RUN_AS_NODE (the TypeScript server and vscode-languageclient do), so
// the signal is escalated only alongside hidden-execution context in the file.
// An encoded PowerShell command hides its text as well as its window.
const HIDDEN_WINDOW = /-W(?:indowStyle)?\s+Hidden\b|\bwindowStyle\s*=\s*['"]?hidden|(?:^|\s)-(?:EncodedCommand|enc)(?:\s|$)/i;
// Literal text near a computed script string that suggests it sets a variable.
const SCRIPT_HINT = /\$env:|\b(?:set|export)\s|=\s*['"]?1/i;

export const rules = [
  {
    id: 'electron-run-as-node',
    meta: {
      severity: 'warning',
      mitre: 'T1218.015',
      description: 'Process launched with ELECTRON_RUN_AS_NODE set; an error when the launching function or a local helper it calls hides execution.',
    },
    create(context) {
      const hits = [];
      // Functions (or the program) that contain hidden-execution text. Bundles
      // join unrelated modules, so the context must share the launch's function.
      const hidden = new Set();
      const owner = node => context.scopes.owner(node);
      return {
        CallExpression(node) {
          const method = childProcessCall(context, node);
          if (!method) return;
          for (const arg of node.arguments) {
            const options = context.objectOf(arg);
            if (!options) continue;
            const env = context.objectOf(context.propertyValue(options, 'env'));
            if (!env || !context.hasProperty(env, 'ELECTRON_RUN_AS_NODE')) continue;
            const first = node.arguments[0];
            const execPath = first && context.memberName(first) === 'execPath';
            // A detached, windowless child outlives the editor unseen. Extensions
            // relaunch their own runtime (process.execPath) detached for bundled
            // helper servers, so only another named binary escalates; a malicious
            // extension relaunching process.execPath therefore stays a warning.
            const flag = name => context.resolve(context.propertyValue(options, name));
            const orphan = !execPath && flag('detached') === true && flag('windowsHide') === true;
            hits.push({ node, level: 'warning', hidden: orphan,
              detail: `${method}() with ELECTRON_RUN_AS_NODE in env${execPath ? ', target process.execPath' : ''}${orphan ? ', detached and windowless' : ''}` });
            return;
          }
        },
        '*'(node) {
          const value = context.literalInfo(node)?.value;
          if (!value) {
            if (node.type === 'TemplateElement' && HIDDEN_WINDOW.test(node.value.cooked ?? '')) hidden.add(owner(node));
            return;
          }
          if (HIDDEN_WINDOW.test(value) || HIDDEN_SCRIPT.test(value)) hidden.add(owner(node));
          if (!SCRIPT_SET.test(value)) return;
          // The variable set inside generated shell or PowerShell script text.
          const parent = context.parent(node);
          if (parent?.type === 'BinaryExpression' && context.literalInfo(parent)) return;
          hits.push({ node, level: 'warning', detail: `script text sets ELECTRON_RUN_AS_NODE: ${SCRIPT_SET.exec(value)[0]}` });
        },
        TemplateLiteral(node) {
          if (!node.expressions.length) return;
          if (node.quasis.some(q => SCRIPT_SET.test(q.value.cooked ?? ''))) {
            hits.push({ node, level: 'warning', detail: 'script template sets ELECTRON_RUN_AS_NODE' });
            return;
          }
          // The variable name assembled from fragments or decoded at run time.
          if (!node.quasis.some(q => SCRIPT_HINT.test(q.value.cooked ?? ''))) return;
          const value = context.resolve(node);
          if (typeof value === 'string' && SCRIPT_SET.test(value)) {
            hits.push({ node, level: 'warning', detail: `computed script text sets ELECTRON_RUN_AS_NODE: ${SCRIPT_SET.exec(value)[0]}` });
          }
        },
        BinaryExpression(node) {
          if (node.operator !== '+' || context.literalInfo(node)) return;
          const parent = context.parent(node);
          if (parent?.type === 'BinaryExpression' && parent.operator === '+') return;
          const parts = [];
          context.visit(node, inner => { if (inner.type === 'Literal' && typeof inner.value === 'string') parts.push(inner.value); }, 200);
          if (!parts.some(part => SCRIPT_HINT.test(part))) return;
          const value = context.resolve(node);
          if (typeof value === 'string' && SCRIPT_SET.test(value) && !parts.some(part => SCRIPT_SET.test(part))) {
            hits.push({ node, level: 'warning', detail: `computed script text sets ELECTRON_RUN_AS_NODE: ${SCRIPT_SET.exec(value)[0]}` });
          }
        },
        AssignmentExpression(node) {
          if (node.left.type === 'MemberExpression' && context.memberName(node.left) === 'ELECTRON_RUN_AS_NODE') {
            hits.push({ node, level: 'note', detail: 'assigns ELECTRON_RUN_AS_NODE' });
          }
        },
        'Program:exit'() {
          // Does this function, or a locally defined helper it calls (to depth 3),
          // contain hidden-execution text? Calls into imported modules are not followed.
          const memo = new Map();
          const hides = (fn, depth = 0) => {
            if (hidden.has(fn)) return true;
            if (depth >= 3 || !fn?.body) return false;
            if (memo.has(fn)) return memo.get(fn);
            memo.set(fn, false);
            let found = false;
            context.visit(fn.type === 'Program' ? fn : fn.body, node => {
              if (found || node.type !== 'CallExpression' || node.callee.type !== 'Identifier') return;
              const binding = context.scopes.lookup(node.callee.name, node.callee);
              if (binding?.kind === 'function' && binding.node !== fn && hides(binding.node, depth + 1)) found = true;
            }, 20000);
            memo.set(fn, found);
            return found;
          };
          // Script text bound to a variable runs where the variable is used, so
          // those functions count as launching code too.
          const users = node => {
            const found = [owner(node)];
            let current = node;
            for (let parent = context.parent(current); parent && !parent.type.endsWith('Statement') && parent.type !== 'VariableDeclarator';
              current = parent, parent = context.parent(current)) ;
            const declarator = context.parent(current)?.type === 'VariableDeclarator' ? context.parent(current) : undefined;
            if (declarator?.id.type !== 'Identifier' || declarator.init !== current) return found;
            const binding = context.scopes.lookup(declarator.id.name, declarator.id);
            for (const other of context.order) {
              if (found.length > 20) break;
              if (other.type !== 'Identifier' || other.name !== declarator.id.name || other === declarator.id) continue;
              if (context.scopes.lookup(other.name, other) === binding) found.push(owner(other));
            }
            return found;
          };
          for (const hit of hits) {
            const escalate = hit.hidden || users(hit.node).some(fn => hides(fn));
            const severity = escalate ? (hit.level === 'note' ? 'warning' : 'error') : hit.level;
            context.report({ node: hit.node, severity, detail: escalate ? `${hit.detail}; the launching code hides execution` : hit.detail });
          }
        },
      };
    },
  },
  {
    id: 'child-process-hidden-script',
    meta: {
      severity: 'warning',
      mitre: 'T1059',
      description: 'Child process runs a script from a temporary or .vscode directory.',
    },
    create(context) {
      return {
        CallExpression(node) {
          const method = childProcessCall(context, node);
          if (!method) return;
          const parts = [];
          for (const arg of node.arguments) {
            const value = context.resolve(arg);
            if (typeof value === 'string') parts.push(value);
            else if (Array.isArray(value)) parts.push(...value.filter(x => typeof x === 'string'));
            else parts.push(...context.fragments(arg));
          }
          const text = parts.join(' ');
          const match = HIDDEN_SCRIPT.exec(text);
          if (match) context.report({ node, detail: `${method}(): ${match[0].trim().slice(0, 160)}` });
        },
      };
    },
  },
];

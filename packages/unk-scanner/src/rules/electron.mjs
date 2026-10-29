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
const HIDDEN_WINDOW = /-W(?:indowStyle)?\s+Hidden\b|\bwindowStyle\s*=\s*['"]?hidden/i;

export const rules = [
  {
    id: 'electron-run-as-node',
    meta: {
      severity: 'warning',
      mitre: 'T1218.015',
      description: 'Process launched with ELECTRON_RUN_AS_NODE set; an error when the file also hides execution.',
    },
    create(context) {
      const hits = [];
      let hidden = false;
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
            hits.push({ node, level: 'warning', detail: `${method}() with ELECTRON_RUN_AS_NODE in env${execPath ? ', target process.execPath' : ''}` });
            return;
          }
        },
        '*'(node) {
          const value = context.literalInfo(node)?.value;
          if (!value) {
            if (node.type === 'TemplateElement' && HIDDEN_WINDOW.test(node.value.cooked ?? '')) hidden = true;
            return;
          }
          if (HIDDEN_WINDOW.test(value) || HIDDEN_SCRIPT.test(value)) hidden = true;
          if (!SCRIPT_SET.test(value)) return;
          // The variable set inside generated shell or PowerShell script text.
          const parent = context.parent(node);
          if (parent?.type === 'BinaryExpression' && context.literalInfo(parent)) return;
          hits.push({ node, level: 'warning', detail: `script text sets ELECTRON_RUN_AS_NODE: ${SCRIPT_SET.exec(value)[0]}` });
        },
        TemplateLiteral(node) {
          if (node.expressions.length && node.quasis.some(q => SCRIPT_SET.test(q.value.cooked ?? ''))) {
            hits.push({ node, level: 'warning', detail: 'script template sets ELECTRON_RUN_AS_NODE' });
          }
        },
        AssignmentExpression(node) {
          if (node.left.type === 'MemberExpression' && context.memberName(node.left) === 'ELECTRON_RUN_AS_NODE') {
            hits.push({ node, level: 'note', detail: 'assigns ELECTRON_RUN_AS_NODE' });
          }
        },
        'Program:exit'() {
          for (const hit of hits) {
            const severity = hidden ? (hit.level === 'note' ? 'warning' : 'error') : hit.level;
            context.report({ node: hit.node, severity, detail: hidden ? `${hit.detail}; file also hides execution` : hit.detail });
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

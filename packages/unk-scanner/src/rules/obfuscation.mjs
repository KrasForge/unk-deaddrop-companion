import { encryptedLoaders } from '../loaders.mjs';

const INTERESTING = /^(?:https?|wss?|ftp):\/\/[^/\s]+|^(?:child_process|vscode|crypto|fs|net|http|https|os|vm|module|worker_threads)$/;
const MODULE_CALLS = new Set(['require', 'import']);

export const rules = [
  {
    id: 'string-array-obfuscation',
    meta: {
      severity: 'warning',
      mitre: 'T1027',
      description: 'obfuscator.io-style string array; reports whether its decoder and rotation were recovered.',
    },
    create(context) {
      return {
        'Program:exit'() {
          for (const array of context.deobfuscation.arrays) {
            const detail = array.method === 'unresolved'
              ? `string array ${array.array} (${array.strings} entries, ${array.variant} decoder): rotation not recovered; ${array.callSites} call sites unresolved`
              : `string array ${array.array} resolved: ${array.decodedSites}/${array.callSites} call sites decoded (${array.variant}, offset ${array.offset}, rotation ${array.rotation} by ${array.method})`;
            context.report({ node: array.node, detail });
          }
        },
      };
    },
  },
  {
    id: 'obfuscated-string-indicator',
    meta: {
      // Context for the string-array finding: what the hidden strings reveal.
      severity: 'note',
      mitre: 'T1027',
      description: 'A string recovered from an obfuscated string array is a URL or a sensitive module name.',
    },
    create(context) {
      return {
        '*'(node) {
          const info = context.literalInfo(node);
          if (!info?.deobfuscated) return;
          const parent = context.parent(node);
          // Report the outermost folded concatenation only.
          if (parent?.type === 'BinaryExpression' && parent.operator === '+' && context.literalInfo(parent)) return;
          const call = parent?.type === 'CallExpression' && parent.arguments[0] === node ? parent : undefined;
          const moduleName = call && call.callee.type === 'Identifier' && MODULE_CALLS.has(call.callee.name);
          if (!INTERESTING.test(info.value) || (!moduleName && !/^[a-z]+:\/\/[^/\s]+/i.test(info.value))) return;
          context.report({
            node,
            detail: `${moduleName ? `${call.callee.name}('${info.value}')` : info.value.slice(0, 240)} (resolved from string array)`,
          });
        },
      };
    },
  },
  {
    id: 'encrypted-loader',
    meta: {
      severity: 'error',
      mitre: 'T1027.013',
      description: 'Embedded base64, AES-GCM authentication and decoded text linked syntactically to Module._compile.',
    },
    create(context) {
      return {
        'Program:exit'() {
          for (const loader of encryptedLoaders(context.ast, node => context.literal(node), context.position)) {
            context.report({
              node: loader.node,
              detail: 'Embedded base64, AES-GCM authentication, and decoded text linked syntactically to _compile',
              data: { evidence: loader.evidence },
            });
          }
        },
      };
    },
  },
];

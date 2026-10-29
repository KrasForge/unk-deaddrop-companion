// Clipboard writes, split by context. A copy button that writes an element's
// text is ordinary; a value that resolves to a terminal command, or a global
// copy handler that replaces the user's selection, is the ClickFix shape.

const COMMAND_PATTERNS = [
  ['pipe-to-shell', /\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/i],
  ['download-cradle', /\b(?:curl|wget)\b[^\n]{0,200}(?:\||&&|;|-o\s)/i],
  ['powershell-hidden', /\bpowershell(?:\.exe)?\b[^\n]{0,200}(?:-w(?:indowstyle)?\s+h(?:idden)?\b|-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}|-nop\b)/i],
  ['powershell-download', /\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient|DownloadString)\b/i],
  ['invoke-expression', /\b(?:iex|Invoke-Expression)\b/i],
  ['mshta', /\bmshta(?:\.exe)?\b/i],
  ['cmd-exec', /\bcmd(?:\.exe)?\s+\/[ck]\b/i],
  ['base64-decode', /\bbase64\s+(?:-d|--decode|-D)\b|FromBase64String/i],
  ['detached-exec', /\b(?:nohup|setsid|disown)\b|perl\s+-MPOSIX/i],
  ['osascript', /\bosascript\s+-e\b/i],
  ['msiexec', /\bmsiexec(?:\.exe)?\b[^\n]{0,120}\/q/i],
  ['rundll32', /\brundll32(?:\.exe)?\b/i],
];
// Lure text that disguises a command as a verification step.
const LURE = /\bverif(?:y|ication)\b|\bcaptcha\b|not a robot|\bI am human\b|VERIFY-|(?:^|\s)#\s+\S/i;
const STRONG = new Set(['powershell-hidden', 'mshta', 'base64-decode', 'detached-exec']);
const SOURCE_PROPERTIES = /^(?:innerText|textContent|value|outerText|innerHTML|dataset|getAttribute)$/;
const SELECTION = /^(?:getSelection|selection|toString)$/;

function commandIndicators(text) {
  return COMMAND_PATTERNS.filter(([, pattern]) => pattern.test(text)).map(([name]) => name);
}

export const rules = [
  {
    id: 'clipboard-write',
    meta: { severity: 'note', description: 'Programmatic clipboard write; benign copy buttons also produce this.' },
    create(context) {
      return {
        CallExpression(node) {
          const write = context.clipboardWrite(node);
          if (!write) return;
          const text = context.resolve(write.arg);
          context.report({ node, detail: typeof text === 'string' ? text.slice(0, 240) : 'dynamic argument; unresolved' });
        },
      };
    },
  },
  {
    id: 'clickfix-clipboard-command',
    meta: {
      severity: 'error',
      mitre: 'T1204.004',
      description: 'Clipboard write whose value resolves to a terminal command (ClickFix pattern).',
    },
    create(context) {
      return {
        CallExpression(node) {
          const write = context.clipboardWrite(node);
          if (!write) return;
          const resolved = context.resolve(write.arg);
          const exact = typeof resolved === 'string';
          let parts = exact ? [resolved] : context.fragments(write.arg);
          let viaCaller = false;
          if (!exact && !commandIndicators(parts.join('\n')).length) {
            // A generic copy helper: look at what its callers pass in.
            const callerParts = context.callerArguments(write.arg).flatMap(arg => context.fragments(arg));
            if (commandIndicators(callerParts.join('\n')).length) { parts = callerParts; viaCaller = true; }
          }
          const text = parts.join('\n');
          if (!text) return;
          const indicators = commandIndicators(text);
          if (!indicators.length) return;
          const listener = context.copyListener(node);
          const lure = LURE.test(text);
          // A plain `curl ... | sh` install command is common on documentation sites,
          // so it is a warning unless something else matches the ClickFix shape.
          const strong = indicators.some(name => STRONG.has(name));
          const severity = listener || lure || strong ? 'error' : 'warning';
          const reasons = [...indicators, ...(listener ? ['copy-event-override'] : []), ...(lure ? ['verification-lure-text'] : [])];
          // For an unresolved value, quote the fragment that matched, not the whole harvest.
          const excerpt = exact ? text : (parts.find(part => commandIndicators(part).length) ?? parts.join(' '));
          context.report({
            node, severity,
            detail: `${reasons.join(', ')}${exact ? '' : viaCaller ? ' (text passed by callers)' : ' (text from builder code)'}: ${excerpt.replace(/\s+/g, ' ').trim().slice(0, 200)}`,
            data: { indicators: reasons, resolved: exact },
          });
        },
      };
    },
  },
  {
    id: 'clipboard-copy-override',
    meta: {
      // Rich-text editors and terminals override copy legitimately; the
      // ClickFix rule escalates when the replacement is a command.
      severity: 'note',
      mitre: 'T1204.004',
      description: 'Copy or cut event handler replaces clipboard content with data not derived from the selection.',
    },
    create(context) {
      return {
        CallExpression(node) {
          const write = context.clipboardWrite(node);
          if (!write || write.method !== 'setData') return;
          const listener = context.copyListener(node);
          if (!listener) return;
          let derived = false;
          context.visit(write.arg, inner => {
            const name = context.memberName(inner) ?? (inner.type === 'Identifier' ? inner.name : undefined);
            if (name && SELECTION.test(name)) derived = true;
          });
          if (derived) return;
          let fromElement = false;
          context.visit(write.arg, inner => {
            const name = context.memberName(inner);
            if (name && SOURCE_PROPERTIES.test(name)) fromElement = true;
          });
          context.report({
            node,
            detail: `${listener.event} handler on ${listener.target} writes ${fromElement ? 'element text' : 'replacement data'}`,
          });
        },
      };
    },
  },
];

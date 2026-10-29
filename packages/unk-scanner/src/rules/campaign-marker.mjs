// Investigation-specific strings and identifiers. A marker is context for
// review; similar strings occur in benign code (for example Electron detection).
const MARKERS = /OVERLORD_COMPANY_WALLET_EP|OVERLORD_SERVER_RAW|OVERLORD_KEEP_AGENT_STATE|X-Company-Wallet-Client-Id|\/api\/company-wallet\/upload|GoogleUpdateSupporterNode|GUS_UPLOAD_CHUNK_SIZE|DEFAULT_PHASE3_MAX_MS|DEFAULT_PHASE3_ROOT_MAX_MS|WIN_NODE_AGENT_BUNDLE_B64|DEFAULT_WALK_MAX_DIRS|CREDENTIAL_NAME_RE|macTccReadableCache|CloudStorage|ELECTRON_RUN_AS_NODE|--company-wallet-phase1-local|--company-wallet-job|--win-build-ep-only|cmdline_copied|perl -MPOSIX|POSIX::setsid|curl -ks|start -WindowStyle Hidden cmd|VERIFY-|IElevator|detect_malware\.py|3E5FC7F9-9A51-4367-9063-A120244FBEC7|gus-phase2-|sa-elev-done-|app_bound_encrypted_key/g;

const IDENTIFIER_MARKERS = new Set([
  'OVERLORD_COMPANY_WALLET_EP', 'OVERLORD_SERVER_RAW', 'OVERLORD_KEEP_AGENT_STATE',
  'GUS_UPLOAD_CHUNK_SIZE', 'DEFAULT_PHASE3_MAX_MS', 'DEFAULT_PHASE3_ROOT_MAX_MS',
  'WIN_NODE_AGENT_BUNDLE_B64', 'DEFAULT_WALK_MAX_DIRS', 'CREDENTIAL_NAME_RE',
  'macTccReadableCache', 'ELECTRON_RUN_AS_NODE', 'app_bound_encrypted_key',
]);

export const rule = {
  id: 'campaign-marker',
  meta: {
    severity: 'note',
    description: 'String or identifier observed in UNK_DeadDrop source; context for review, not a verdict.',
  },
  create(context) {
    return {
      Identifier(node) {
        if (IDENTIFIER_MARKERS.has(node.name)) context.report({ node, detail: node.name });
      },
      '*'(node) {
        if (node.type === 'Identifier') return;
        const info = context.literalInfo(node);
        if (!info) return;
        for (const match of info.value.matchAll(MARKERS)) {
          // Report a marker once, at the outermost folded expression.
          if (context.coveredBy(node, match[0])) continue;
          context.report({ node, detail: match[0], ...(info.deobfuscated ? { via: 'string-array' } : {}) });
        }
      },
    };
  },
};

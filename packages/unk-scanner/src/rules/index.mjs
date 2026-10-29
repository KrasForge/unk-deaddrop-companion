// Built-in rules. Each rule is { id, meta: { severity, description, mitre? },
// create(context) } and returns visitors keyed by ESTree node type, '*' for
// every node, or 'Program:exit'.
import { rule as campaignMarker } from './campaign-marker.mjs';
import { rules as clipboard } from './clipboard.mjs';
import { rules as electron } from './electron.mjs';
import { rules as obfuscation } from './obfuscation.mjs';

export const builtinRules = [campaignMarker, ...clipboard, ...electron, ...obfuscation];

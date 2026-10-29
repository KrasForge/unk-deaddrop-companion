// Builds an inert obfuscator.io-style test input: a rotated, RC4/base64-encoded
// string array, a decoder, a wrapper and a checksum rotation loop. The strings
// are harmless; the scanner must recover them without running this code.
const STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const swapCase = s => s.replace(/[a-z]/gi, c => c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase());

function rc4(text, key) {
  const s = Array.from({ length: 256 }, (_, i) => i);
  let j = 0;
  for (let i = 0; i < 256; i++) { j = (j + s[i] + key.charCodeAt(i % key.length)) % 256; [s[i], s[j]] = [s[j], s[i]]; }
  let i = 0; j = 0; let out = '';
  for (let k = 0; k < text.length; k++) {
    i = (i + 1) % 256; j = (j + s[i]) % 256; [s[i], s[j]] = [s[j], s[i]];
    out += String.fromCharCode(text.charCodeAt(k) ^ s[(s[i] + s[j]) % 256]);
  }
  return out;
}

export function obfuscatedFixture({ strings, rotation = 7, offset = 0x1a3, variant = 'rc4', checksum = true, minified = false }) {
  const keys = strings.map((_, i) => 'k' + ((i * 7919) % 97).toString(36) + '!');
  const encode = (text, key) => {
    const plain = variant === 'rc4' ? rc4(text, key) : text;
    return swapCase(Buffer.from(plain, 'utf8').toString('base64'));
  };
  const encoded = strings.map((text, i) => encode(text, keys[i]));
  // Store the array rotated so that `rotation` left shifts restore source order.
  const n = encoded.length;
  const stored = encoded.map((_, i) => encoded[(i - rotation + n * 8) % n]);
  const numeric = strings.map((text, i) => [i, Number.parseInt(text)]).filter(([, v]) => Number.isFinite(v)).slice(0, 4);
  const wrapperCall = i => `_0xw(0x0, ${'0x' + (i + offset - 0x10).toString(16)}, '${keys[i].replace(/'/g, "\\'")}')`;
  const terms = numeric.map(([i], k) => `${k % 2 ? '-' : ''}parseInt(${wrapperCall(i)})/0x${(k + 1).toString(16)}`);
  const target = numeric.reduce((sum, [, v], k) => sum + (k % 2 ? -v : v) / (k + 1), 0);
  const keyParam = variant === 'rc4' ? '_0xk' : '_0xunused';
  const lines = [
    `function _0xarr(){const _0xa=${JSON.stringify(stored).replace(/"/g, "'")};_0xarr=function(){return _0xa;};return _0xarr();}`,
    `function _0xdec(_0xi,${keyParam}){_0xi=_0xi-(0x${offset.toString(16)});const _0xs=_0xarr();let _0xv=_0xs[_0xi];` +
      `const _0xal='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';` +
      (variant === 'rc4' ? `const _0xsz=0x80+0x80;_0xv=_0xv+${keyParam};` : '') + `return _0xv;}`,
    `function _0xw(_0xa,_0xb,_0xc){return _0xdec(_0xb- -0x10,_0xc);}`,
  ];
  if (!checksum && rotation) {
    // Older obfuscator output: rotate a fixed number of times, no checksum.
    lines.push(`(function(_0xg,_0xn){const _0xq=_0xg();const _0xf=function(_0xk){while(--_0xk){_0xq['push'](_0xq['shift']());}};_0xf(++_0xn);}(_0xarr,${rotation}));`);
  }
  if (checksum && minified) {
    // Minifier-style loop: no parameters, array fetched by name, literal target.
    lines.push(`(function(){const _0xq=_0xarr();for(;;)try{if(${target}==${terms.join('+') || '0'})break;_0xq.push(_0xq.shift())}catch(_0xe){_0xq.push(_0xq.shift())}}());`);
  } else if (checksum) {
    lines.push(`(function(_0xg,_0xt){const _0xq=_0xg();while(!![]){try{const _0xc=${terms.join('+') || '0'};` +
      `if(_0xc===_0xt)break;else _0xq['push'](_0xq['shift']());}catch(_0xe){_0xq['push'](_0xq['shift']());}}}(_0xarr,${target}));`);
  }
  const call = text => wrapperCall(strings.indexOf(text));
  return { source: lines.join('\n') + '\n', call, keys };
}

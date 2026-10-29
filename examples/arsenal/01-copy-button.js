// Inert Arsenal demo: an ordinary documentation "copy" button.
// Expected: clipboard-write (note) only.
document.querySelectorAll('pre > button.copy').forEach(button => {
  button.addEventListener('click', () => {
    navigator.clipboard.writeText(button.parentElement.querySelector('code').innerText);
  });
});

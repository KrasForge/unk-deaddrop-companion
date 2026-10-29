// Inert Arsenal demo: the same technique as the UNK_DeadDrop Windows branch,
// with placeholder paths. A generated PowerShell script sets the variable and the
// launcher hides its window. Expected: electron-run-as-node (error).
const script = [
  "$env:ELECTRON_RUN_AS_NODE = '1'",
  "& 'C:\\Placeholder\\Editor.exe' 'C:\\Placeholder\\agent.js'",
].join('\r\n');
const launcher = '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File demo.ps1';
void script; void launcher;

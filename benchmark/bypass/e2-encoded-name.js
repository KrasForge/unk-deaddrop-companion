// Inert bypass variant for the scanner paper (RQ3): placeholder values only,
// and the scanner never runs this file.
// Change: the variable name is base64-decoded at run time.
const name = Buffer.from('RUxFQ1RST05fUlVOX0FTX05PREU=', 'base64').toString();
const script = [`$env:${name} = '1'`, "& 'C:\\Placeholder\\Editor.exe' 'C:\\Placeholder\\agent.js'"].join('\r\n');
const launcher = '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File demo.ps1';
void script; void launcher;

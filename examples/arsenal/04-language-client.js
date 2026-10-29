// Inert Arsenal demo: how legitimate VS Code language clients start a server.
// Expected: electron-run-as-node (warning). This pattern is common and benign.
const { spawn } = require('child_process');

function launchServer(serverModule) {
  return spawn(process.execPath, [serverModule], { env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' } });
}
void launchServer;

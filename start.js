// start.js (Root Workspace Coordinator)
const { spawn, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const serverDir = path.join(__dirname, 'USBRemote', 'Server');
const clientDir = path.join(__dirname, 'USBRemote', 'Client');

console.log('[Workspace] Initializing USB Remote Connect Project...');

// Helper to install dependencies
function ensureDependencies(dir, name) {
  const nodeModulesPath = path.join(dir, 'node_modules');
  if (!fs.existsSync(nodeModulesPath)) {
    console.log(`[Workspace] Dependencies missing for ${name}. Running 'npm install' in ${dir}...`);
    try {
      execSync('npm install', { cwd: dir, stdio: 'inherit' });
      console.log(`[Workspace] Dependencies successfully installed for ${name}.`);
    } catch (err) {
      console.error(`[Workspace] Failed to install dependencies for ${name}:`, err.message);
      process.exit(1);
    }
  } else {
    console.log(`[Workspace] Dependencies verified for ${name}.`);
  }
}

// Ensure dependencies are installed
ensureDependencies(serverDir, 'Signaling Server');
ensureDependencies(clientDir, 'Electron Client');

console.log('[Workspace] Launching sub-services...');

// Launch Server
const serverProcess = spawn('node', ['server.js'], {
  cwd: serverDir,
  shell: true
});

serverProcess.stdout.on('data', (data) => {
  process.stdout.write(`[Server] ${data}`);
});

serverProcess.stderr.on('data', (data) => {
  process.stderr.write(`[Server-Error] ${data}`);
});

// Launch Client (spawns start.js which runs Vite and Electron)
const clientProcess = spawn('node', ['start.js'], {
  cwd: clientDir,
  shell: true
});

clientProcess.stdout.on('data', (data) => {
  process.stdout.write(`[Client] ${data}`);
});

clientProcess.stderr.on('data', (data) => {
  process.stderr.write(`[Client-Error] ${data}`);
});

// Manage teardown
function cleanup() {
  console.log('[Workspace] Cleaning up processes...');
  if (process.platform === 'win32') {
    // Kill process trees on Windows
    spawn('taskkill', ['/pid', serverProcess.pid, '/f', '/t']);
    spawn('taskkill', ['/pid', clientProcess.pid, '/f', '/t']);
  } else {
    serverProcess.kill();
    clientProcess.kill();
  }
}

serverProcess.on('close', (code) => {
  console.log(`[Workspace] Server exited with code ${code}.`);
  cleanup();
  process.exit(code);
});

clientProcess.on('close', (code) => {
  console.log(`[Workspace] Client exited with code ${code}.`);
  cleanup();
  process.exit(code);
});

// Capture Ctrl+C / SIGINT
process.on('SIGINT', () => {
  cleanup();
  process.exit(0);
});

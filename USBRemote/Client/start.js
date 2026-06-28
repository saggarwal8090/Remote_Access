// USBRemote/Client/start.js
const { spawn } = require('child_process');
const path = require('path');

console.log('[DevStart] Initializing USB Remote Connect Dev Environment...');

// Spawn Vite Dev Server
const vite = spawn('npx.cmd', ['vite'], {
  stdio: 'inherit',
  shell: true
});

let electronStarted = false;

// Wait for a short duration to ensure Vite has started, then launch Electron
setTimeout(() => {
  if (electronStarted) return;
  electronStarted = true;

  console.log('[DevStart] Launching Electron window...');

  const electron = spawn('npx.cmd', ['electron', '.'], {
    env: { ...process.env, NODE_ENV: 'development' },
    stdio: 'inherit',
    shell: true
  });

  electron.on('close', (code) => {
    console.log(`[DevStart] Electron process exited with code ${code}. Shutting down Vite...`);
    // Kill Vite
    if (process.platform === 'win32') {
      spawn('taskkill', ['/pid', vite.pid, '/f', '/t']);
    } else {
      vite.kill();
    }
    process.exit(code);
  });

}, 2000);

vite.on('close', (code) => {
  console.log(`[DevStart] Vite process exited with code ${code}.`);
  if (!electronStarted) {
    process.exit(code);
  }
});

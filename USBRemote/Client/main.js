// USBRemote/Client/main.js
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');

// Import helper services
const logger = require('../Shared/logger');
const config = require('../Shared/config');
const usbDetector = require('../USB/usb-detector');
const certManager = require('../USB/cert-manager');
const cryptoHelper = require('../Network/crypto-helper');

let mainWindow = null;
let dbPath = null;

// Initialize directories and databases
function initDatabase() {
  const userDataDir = app.getPath('userData');
  logger.init(userDataDir);
  
  dbPath = path.join(userDataDir, config.DB_FILENAME);
  if (!fs.existsSync(dbPath)) {
    try {
      fs.writeFileSync(dbPath, JSON.stringify([], null, 2), 'utf8');
      logger.info('DB', 'Trusted devices database initialized.');
    } catch (err) {
      console.error('Failed to create trusted database file:', err);
    }
  }
}

// Load trusted devices
function getTrustedDevices() {
  if (!dbPath || !fs.existsSync(dbPath)) return [];
  try {
    const content = fs.readFileSync(dbPath, 'utf8');
    return JSON.parse(content || '[]');
  } catch (err) {
    logger.error('DB', 'Failed to read trusted database', { error: err.message });
    return [];
  }
}

// Save trusted device
function addTrustedDevice(device) {
  const list = getTrustedDevices();
  // Avoid duplicate ID registration
  const exists = list.some(item => item.id === device.id);
  if (exists) {
    return { success: true, message: 'Device already trusted.' };
  }
  
  list.push({
    id: device.id,
    label: device.label,
    owner: device.owner,
    publicKey: device.publicKey,
    addedAt: new Date().toISOString()
  });

  try {
    fs.writeFileSync(dbPath, JSON.stringify(list, null, 2), 'utf8');
    logger.security('DB', `Added device ${device.label} (${device.id}) to trusted list.`);
    return { success: true };
  } catch (err) {
    logger.error('DB', 'Failed to save trusted device', { error: err.message });
    return { success: false, error: err.message };
  }
}

// Remove trusted device
function removeTrustedDevice(id) {
  let list = getTrustedDevices();
  const initialLen = list.length;
  list = list.filter(item => item.id !== id);

  if (list.length === initialLen) {
    return { success: false, error: 'Device not found.' };
  }

  try {
    fs.writeFileSync(dbPath, JSON.stringify(list, null, 2), 'utf8');
    logger.security('DB', `Removed device ID ${id} from trusted list.`);
    return { success: true };
  } catch (err) {
    logger.error('DB', 'Failed to remove trusted device', { error: err.message });
    return { success: false, error: err.message };
  }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1080,
    height: 780,
    minWidth: 800,
    minHeight: 600,
    title: 'USB Remote Connect',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    },
    // Modern title bar
    titleBarStyle: 'hiddenInset',
    backgroundColor: '#0b0f19'
  });

  // Load URL depending on environment
  const isDev = process.env.NODE_ENV === 'development';
  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
    // Open DevTools
    mainWindow.webContents.openDevTools();
    
    // Auto-retry if load fails (e.g. Vite still booting)
    mainWindow.webContents.on('did-fail-load', () => {
      logger.warn('NET', 'Connection to Vite dev server failed. Retrying in 1s...');
      setTimeout(() => {
        if (mainWindow) mainWindow.loadURL('http://localhost:5173');
      }, 1000);
    });
  } else {
    mainWindow.loadFile(path.join(__dirname, 'dist', 'index.html'));
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// Set up IPC event handlers
function setupIPCHandlers() {
  // USB
  ipcMain.handle('usb:get-drives', () => usbDetector.getConnectedDrives());
  ipcMain.handle('usb:register', (event, letter, label) => certManager.registerUSBDrive(letter, label));
  ipcMain.handle('usb:read', (event, letter) => certManager.readUSBKey(letter));
  ipcMain.handle('usb:add-simulated', (event, path, label) => usbDetector.addSimulatedUSB(path, label));
  ipcMain.handle('usb:remove-simulated', (event, path) => usbDetector.removeSimulatedUSB(path));

  // Host Info
  ipcMain.handle('sys:get-computer-name', () => os.hostname());

  // Database
  ipcMain.handle('db:get-trusted', () => getTrustedDevices());
  ipcMain.handle('db:add-trusted', (event, device) => addTrustedDevice(device));
  ipcMain.handle('db:remove-trusted', (event, id) => removeTrustedDevice(id));

  // Crypto Operations
  ipcMain.handle('crypto:sign-challenge', (event, challenge, pKey) => cryptoHelper.signChallenge(challenge, pKey));
  ipcMain.handle('crypto:verify-challenge', (event, challenge, sig, pubKey) => cryptoHelper.verifyChallenge(challenge, sig, pubKey));

  // Logs
  ipcMain.handle('logs:get', () => logger.getLogs());
  ipcMain.handle('logs:clear', () => {
    logger.clearLogs();
    return true;
  });
}

// Listen for USB plug-in events and push to React frontend
function setupUSBEventListeners() {
  usbDetector.on('connect', (drive) => {
    if (mainWindow) {
      mainWindow.webContents.send('usb:on-change', { event: 'connect', drive });
    }
  });

  usbDetector.on('disconnect', (drive) => {
    if (mainWindow) {
      mainWindow.webContents.send('usb:on-change', { event: 'disconnect', drive });
    }
  });
}

// Application lifecycle
app.whenReady().then(() => {
  initDatabase();
  setupIPCHandlers();
  setupUSBEventListeners();
  
  // Start background monitoring for physical USB keys
  usbDetector.startMonitoring();

  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  usbDetector.stopMonitoring();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// USBRemote/Client/preload.js
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // USB Operations
  getConnectedDrives: () => ipcRenderer.invoke('usb:get-drives'),
  registerUSBDrive: (driveLetter, keyLabel) => ipcRenderer.invoke('usb:register', driveLetter, keyLabel),
  readUSBKey: (driveLetter) => ipcRenderer.invoke('usb:read', driveLetter),
  addSimulatedUSB: (dirPath, label) => ipcRenderer.invoke('usb:add-simulated', dirPath, label),
  removeSimulatedUSB: (dirPath) => ipcRenderer.invoke('usb:remove-simulated', dirPath),
  onUSBChange: (callback) => {
    const subscription = (event, data) => callback(data);
    ipcRenderer.on('usb:on-change', subscription);
    return () => ipcRenderer.removeListener('usb:on-change', subscription);
  },

  // Host Details
  getComputerName: () => ipcRenderer.invoke('sys:get-computer-name'),

  // Trusted Devices (Local Database / JSON store)
  getTrustedDevices: () => ipcRenderer.invoke('db:get-trusted'),
  addTrustedDevice: (device) => ipcRenderer.invoke('db:add-trusted', device),
  removeTrustedDevice: (id) => ipcRenderer.invoke('db:remove-trusted', id),

  // Crypto Helpers
  signChallenge: (challenge, privateKeyPEM) => ipcRenderer.invoke('crypto:sign-challenge', challenge, privateKeyPEM),
  verifyChallenge: (challenge, signature, publicKeyPEM) => ipcRenderer.invoke('crypto:verify-challenge', challenge, signature, publicKeyPEM),

  // Security Logs
  getLogs: () => ipcRenderer.invoke('logs:get'),
  clearLogs: () => ipcRenderer.invoke('logs:clear')
});

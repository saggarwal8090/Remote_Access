// USBRemote/USB/usb-detector.js
const { exec } = require('child_process');
const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const logger = require('../Shared/logger');

class USBDetector extends EventEmitter {
  constructor() {
    super();
    this.intervalId = null;
    this.connectedDrives = new Map(); // Map of driveLetter -> driveInfo
    this.isScanning = false;
    this.simulatorDrives = new Map(); // Map of simulatedPath -> driveInfo (for developer simulation)
  }

  // Start polling for USB drives (runs on Windows)
  startMonitoring(intervalMs = 2000) {
    if (this.intervalId) return;

    logger.info('USB', 'Starting USB drive monitoring.');
    this.scan(); // Initial scan
    this.intervalId = setInterval(() => this.scan(), intervalMs);
  }

  // Stop polling
  stopMonitoring() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
      logger.info('USB', 'Stopped USB drive monitoring.');
    }
  }

  // Scan for physical drives using PowerShell
  scan() {
    if (this.isScanning) return;
    this.isScanning = true;

    // Command to fetch removable volumes in JSON format
    const cmd = `powershell -Command "Get-Volume | Where-Object DriveType -eq Removable | Select-Object DriveLetter, FriendlyName, Size, SizeRemaining | ConvertTo-Json"`;
    
    exec(cmd, (err, stdout) => {
      this.isScanning = false;
      if (err) {
        // Fallback: If PowerShell is not configured, we don't crash.
        return;
      }

      const stdoutTrimmed = stdout.trim();
      let detectedDrivesList = [];

      if (stdoutTrimmed) {
        try {
          const parsed = JSON.parse(stdoutTrimmed);
          detectedDrivesList = Array.isArray(parsed) ? parsed : [parsed];
        } catch (e) {
          // JSON parse failed, might be single entry with odd formatting
        }
      }

      // Filter drives that have a valid drive letter
      const activeLetters = new Set();
      const currentList = [];

      // Process physical drives
      for (const drive of detectedDrivesList) {
        if (drive && drive.DriveLetter) {
          const letter = `${drive.DriveLetter}:`;
          activeLetters.add(letter);
          currentList.push({
            driveLetter: letter,
            label: drive.FriendlyName || 'Removable Disk',
            size: drive.Size || 0,
            isSimulated: false
          });
        }
      }

      // Process simulated drives
      for (const [simPath, driveInfo] of this.simulatorDrives.entries()) {
        if (fs.existsSync(simPath)) {
          activeLetters.add(simPath);
          currentList.push({
            driveLetter: simPath,
            label: driveInfo.label,
            size: 0,
            isSimulated: true
          });
        } else {
          // Simulated path went offline (e.g. folder deleted)
          this.simulatorDrives.delete(simPath);
        }
      }

      // 1. Detect disconnected drives
      for (const letter of this.connectedDrives.keys()) {
        if (!activeLetters.has(letter)) {
          const driveInfo = this.connectedDrives.get(letter);
          this.connectedDrives.delete(letter);
          logger.info('USB', `USB drive disconnected: ${letter} (${driveInfo.label})`);
          this.emit('disconnect', driveInfo);
        }
      }

      // 2. Detect newly connected drives
      for (const drive of currentList) {
        if (!this.connectedDrives.has(drive.driveLetter)) {
          this.connectedDrives.set(drive.driveLetter, drive);
          logger.info('USB', `USB drive connected: ${drive.driveLetter} (${drive.label}) [Simulated: ${drive.isSimulated}]`);
          this.emit('connect', drive);
        }
      }
    });
  }

  // Get currently connected drives (both physical and simulated)
  getConnectedDrives() {
    return Array.from(this.connectedDrives.values());
  }

  // Simulator helper: Add a local directory to act as a simulated USB key
  addSimulatedUSB(dirPath, label = 'Simulated USB Key') {
    try {
      const resolvedPath = path.resolve(dirPath);
      if (!fs.existsSync(resolvedPath)) {
        fs.mkdirSync(resolvedPath, { recursive: true });
      }

      this.simulatorDrives.set(resolvedPath, {
        driveLetter: resolvedPath,
        label: label,
        isSimulated: true
      });
      
      logger.info('USB', `Simulated USB registered: ${resolvedPath}`);
      this.scan(); // Force scan to trigger insert event
      return { success: true, path: resolvedPath };
    } catch (err) {
      logger.error('USB', `Failed to register simulated USB directory: ${dirPath}`, { error: err.message });
      return { success: false, error: err.message };
    }
  }

  // Simulator helper: Remove a simulated USB key
  removeSimulatedUSB(dirPath) {
    const resolvedPath = path.resolve(dirPath);
    if (this.simulatorDrives.has(resolvedPath)) {
      this.simulatorDrives.delete(resolvedPath);
      logger.info('USB', `Simulated USB removed: ${resolvedPath}`);
      this.scan(); // Force scan to trigger disconnect event
      return true;
    }
    return false;
  }
}

module.exports = new USBDetector();

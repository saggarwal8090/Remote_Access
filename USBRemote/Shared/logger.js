// USBRemote/Shared/logger.js
const fs = require('fs');
const path = require('path');
const config = require('./config');

class Logger {
  constructor() {
    this.logPath = null;
  }

  init(userDataPath) {
    this.logPath = path.join(userDataPath, config.SESSION_LOGS_FILENAME);
    // Create log file if it doesn't exist
    if (!fs.existsSync(this.logPath)) {
      try {
        fs.writeFileSync(this.logPath, JSON.stringify([], null, 2));
      } catch (err) {
        console.error('Failed to initialize log file:', err);
      }
    }
  }

  log(level, category, message, details = {}) {
    const entry = {
      timestamp: new Date().toISOString(),
      level: level.toUpperCase(), // INFO, WARN, ERROR, SECURITY
      category, // e.g. "USB", "NET", "SESSION"
      message,
      details
    };

    console.log(`[${entry.timestamp}] [${entry.level}] [${category}] ${message}`, details);

    if (this.logPath) {
      try {
        const fileContent = fs.readFileSync(this.logPath, 'utf8');
        const logs = JSON.parse(fileContent || '[]');
        logs.push(entry);
        fs.writeFileSync(this.logPath, JSON.stringify(logs, null, 2));
      } catch (err) {
        console.error('Failed to write log to file:', err);
      }
    }
  }

  info(category, message, details) {
    this.log('INFO', category, message, details);
  }

  warn(category, message, details) {
    this.log('WARN', category, message, details);
  }

  error(category, message, details) {
    this.log('ERROR', category, message, details);
  }

  security(category, message, details) {
    this.log('SECURITY', category, message, details);
  }

  getLogs() {
    if (!this.logPath || !fs.existsSync(this.logPath)) return [];
    try {
      return JSON.parse(fs.readFileSync(this.logPath, 'utf8') || '[]');
    } catch (err) {
      return [];
    }
  }

  clearLogs() {
    if (!this.logPath) return;
    try {
      fs.writeFileSync(this.logPath, JSON.stringify([], null, 2));
    } catch (err) {
      console.error('Failed to clear logs:', err);
    }
  }
}

module.exports = new Logger();

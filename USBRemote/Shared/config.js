// USBRemote/Shared/config.js
module.exports = {
  PORT: process.env.PORT || 9000,
  SIGNALING_SERVER_URL: process.env.SIGNALING_URL || 'ws://localhost:9000',
  DB_FILENAME: 'trusted_devices.json',
  SESSION_LOGS_FILENAME: 'session_logs.json',
  CRYPTO: {
    ALGORITHM: 'aes-256-gcm',
    KEY_LENGTH: 32,
    IV_LENGTH: 12,
    TAG_LENGTH: 16
  }
};

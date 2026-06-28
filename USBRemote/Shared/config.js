// USBRemote/Shared/config.js
module.exports = {
  PORT: process.env.PORT || 9000,
  SIGNALING_SERVER_URL: process.env.SIGNALING_URL || 'wss://remote-access-7j7a.onrender.com',
  DB_FILENAME: 'trusted_devices.json',
  SESSION_LOGS_FILENAME: 'session_logs.json',
  CRYPTO: {
    ALGORITHM: 'aes-256-gcm',
    KEY_LENGTH: 32,
    IV_LENGTH: 12,
    TAG_LENGTH: 16
  }
};

// USBRemote/USB/cert-manager.js
const fs = require('fs');
const path = require('path');
const os = require('os');
const cryptoHelper = require('../Network/crypto-helper');
const logger = require('../Shared/logger');

class CertManager {
  constructor() {
    this.folderName = '.usbremote';
  }

  // Get full path to the .usbremote directory on a given drive
  getDir(driveLetter) {
    // Format driveLetter properly (e.g., E: -> E:\)
    let formatted = driveLetter.trim();
    if (!formatted.endsWith(path.sep)) {
      formatted += path.sep;
    }
    return path.join(formatted, this.folderName);
  }

  // Write certificate and private key to the USB drive
  registerUSBDrive(driveLetter, keyLabel) {
    const usbDir = this.getDir(driveLetter);

    try {
      // 1. Create directory if not exists
      if (!fs.existsSync(usbDir)) {
        fs.mkdirSync(usbDir, { recursive: true });
      }

      // 2. Generate RSA Key Pair
      const { publicKey, privateKey } = cryptoHelper.generateRSAKeyPair();

      // 3. Construct certificate metadata
      const certId = cryptoHelper.sha256(publicKey).substring(0, 16);
      const metadata = {
        id: certId,
        label: keyLabel,
        owner: os.hostname(),
        username: os.userInfo().username,
        createdAt: new Date().toISOString(),
        publicKey: publicKey
      };

      // 4. Sign the metadata using the private key to prove it was generated together
      const metaString = JSON.stringify({ id: metadata.id, owner: metadata.owner, createdAt: metadata.createdAt });
      const signature = cryptoHelper.signChallenge(metaString, privateKey);
      metadata.signature = signature;

      // 5. Write to USB
      fs.writeFileSync(path.join(usbDir, 'certificate.json'), JSON.stringify(metadata, null, 2), 'utf8');
      fs.writeFileSync(path.join(usbDir, 'key.pem'), privateKey, 'utf8');

      logger.security('USB', `Successfully registered USB key on drive ${driveLetter}`, { id: certId, label: keyLabel });

      return {
        success: true,
        certificate: metadata
      };
    } catch (err) {
      logger.error('USB', `Failed to register USB key on drive ${driveLetter}`, { error: err.message });
      return {
        success: false,
        error: err.message
      };
    }
  }

  // Read certificate and private key from USB drive
  readUSBKey(driveLetter) {
    const usbDir = this.getDir(driveLetter);
    const certPath = path.join(usbDir, 'certificate.json');
    const keyPath = path.join(usbDir, 'key.pem');

    if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
      return { success: false, error: 'No security credentials found on this drive.' };
    }

    try {
      const certData = JSON.parse(fs.readFileSync(certPath, 'utf8'));
      const privateKey = fs.readFileSync(keyPath, 'utf8');

      // Verify certificate integrity using its signature
      const metaString = JSON.stringify({ id: certData.id, owner: certData.owner, createdAt: certData.createdAt });
      const isValid = cryptoHelper.verifyChallenge(metaString, certData.signature, certData.publicKey);

      if (!isValid) {
        logger.warn('USB', `Certificate signature verification failed on drive ${driveLetter}`);
        return { success: false, error: 'Security key credentials appear corrupted or modified.' };
      }

      return {
        success: true,
        certificate: certData,
        privateKey: privateKey
      };
    } catch (err) {
      logger.error('USB', `Failed to read security key on drive ${driveLetter}`, { error: err.message });
      return { success: false, error: `Error reading key: ${err.message}` };
    }
  }

  // Verify that a given private key belongs to a public key
  verifyKeyPair(privateKey, publicKey) {
    try {
      const challenge = cryptoHelper.generateRandomString();
      const sig = cryptoHelper.signChallenge(challenge, privateKey);
      return cryptoHelper.verifyChallenge(challenge, sig, publicKey);
    } catch (err) {
      return false;
    }
  }
}

module.exports = new CertManager();

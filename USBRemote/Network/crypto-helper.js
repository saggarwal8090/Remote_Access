// USBRemote/Network/crypto-helper.js
const crypto = require('crypto');
const config = require('../Shared/config');

class CryptoHelper {
  // Generate RSA Key Pair for USB authentication
  generateRSAKeyPair() {
    return crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });
  }

  // Sign a challenge with a private key
  signChallenge(challenge, privateKeyPEM) {
    const sign = crypto.createSign('SHA256');
    sign.update(challenge);
    sign.end();
    return sign.sign(privateKeyPEM, 'base64');
  }

  // Verify a challenge signature with a public key
  verifyChallenge(challenge, signatureBase64, publicKeyPEM) {
    try {
      const verify = crypto.createVerify('SHA256');
      verify.update(challenge);
      verify.end();
      return verify.verify(publicKeyPEM, signatureBase64, 'base64');
    } catch (err) {
      console.error('Signature verification error:', err);
      return false;
    }
  }

  // Generate ECDH Key Pair for Session Key Exchange
  generateECDH() {
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.generateKeys();
    return ecdh;
  }

  // Compute AES-256-GCM key from local ECDH and remote ECDH public key
  deriveSharedKey(localECDH, remotePublicKeyBase64) {
    try {
      const remoteKeyBuffer = Buffer.from(remotePublicKeyBase64, 'base64');
      const sharedSecret = localECDH.computeSecret(remoteKeyBuffer);
      // Derive 32-byte key using SHA-256
      return crypto.createHash('sha256').update(sharedSecret).digest();
    } catch (err) {
      console.error('Failed to derive shared key:', err);
      return null;
    }
  }

  // AES-256-GCM Encryption
  encrypt(plaintext, keyBuffer) {
    try {
      const iv = crypto.randomBytes(config.CRYPTO.IV_LENGTH);
      const cipher = crypto.createCipheriv(config.CRYPTO.ALGORITHM, keyBuffer, iv);
      
      let encrypted = cipher.update(plaintext, 'utf8', 'base64');
      encrypted += cipher.final('base64');
      
      const tag = cipher.getAuthTag().toString('base64');
      
      return {
        ciphertext: encrypted,
        iv: iv.toString('base64'),
        tag: tag
      };
    } catch (err) {
      console.error('AES encryption error:', err);
      return null;
    }
  }

  // AES-256-GCM Decryption
  decrypt(ciphertext, keyBuffer, ivBase64, tagBase64) {
    try {
      const iv = Buffer.from(ivBase64, 'base64');
      const tag = Buffer.from(tagBase64, 'base64');
      const decipher = crypto.createDecipheriv(config.CRYPTO.ALGORITHM, keyBuffer, iv);
      decipher.setAuthTag(tag);
      
      let decrypted = decipher.update(ciphertext, 'base64', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (err) {
      console.error('AES decryption error:', err);
      return null;
    }
  }

  // Generate random session ID or challenge
  generateRandomString(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  // Hash a value for quick ID comparison
  sha256(text) {
    return crypto.createHash('sha256').update(text).digest('hex');
  }
}

module.exports = new CryptoHelper();

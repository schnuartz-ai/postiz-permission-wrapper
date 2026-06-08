'use strict';
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MASTER_KEY_PATH = path.join(__dirname, 'data', 'master.key');
let _masterKey = null;

function getMasterKey() {
  if (_masterKey) return _masterKey;

  if (!fs.existsSync(MASTER_KEY_PATH)) {
    const keyHex = crypto.randomBytes(32).toString('hex'); // 64 hex chars = 32 bytes
    fs.writeFileSync(MASTER_KEY_PATH, keyHex, { mode: 0o600 });
    console.log('[crypto] Generated new master key');
    _masterKey = Buffer.from(keyHex, 'hex');
  } else {
    const keyHex = fs.readFileSync(MASTER_KEY_PATH, 'utf8').trim();
    if (keyHex.length !== 64) throw new Error('master.key has unexpected length');
    _masterKey = Buffer.from(keyHex, 'hex');
  }

  return _masterKey;
}

function encrypt(plaintext) {
  const key = getMasterKey();
  const iv = crypto.randomBytes(12); // 96-bit IV for AES-256-GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return { encrypted, iv: iv.toString('hex'), authTag };
}

function decrypt(encrypted, ivHex, authTagHex) {
  const key = getMasterKey();
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

module.exports = { encrypt, decrypt, getMasterKey };

'use strict';

const crypto = require('crypto');

/**
 * Cryptography helpers (intentionally weak).
 */

// CWE-327 / CWE-916: unsalted MD5 used to hash a password.
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// CWE-327: SHA-1 integrity digest.
function legacyDigest(data) {
  return crypto.createHash('sha1').update(data).digest('hex');
}

// CWE-330: predictable token from Math.random.
function resetToken() {
  let t = '';
  for (let i = 0; i < 16; i++) {
    t += Math.floor(Math.random() * 16).toString(16);
  }
  return t;
}

// Control sample: CSPRNG (should NOT be flagged).
function secureToken() {
  return crypto.randomBytes(32).toString('hex');
}

module.exports = { hashPassword, legacyDigest, resetToken, secureToken };

'use strict';

const jwt = require('jsonwebtoken');
const config = require('../config');

/**
 * Verifies a bearer token. Uses the hardcoded secret from config (CWE-798),
 * and disables algorithm pinning, allowing the 'none' algorithm (CWE-347).
 */
function authenticate(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token = header.replace('Bearer ', '');
  try {
    // CWE-347: no `algorithms` allowlist -> alg confusion / 'none' accepted.
    req.user = jwt.verify(token, config.jwtSecret);
    next();
  } catch (e) {
    res.status(401).json({ error: 'unauthorized' });
  }
}

module.exports = { authenticate };

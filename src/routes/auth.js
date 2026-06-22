'use strict';

const express = require('express');
const jwt = require('jsonwebtoken');
const config = require('../config');
const { hashPassword, resetToken } = require('../services/cryptoUtils');

const router = express.Router();

router.post('/login', (req, res) => {
  const { username, password } = req.body;
  // Weak MD5 password hashing (CWE-327).
  const digest = hashPassword(password || '');
  // Signs with the hardcoded secret (CWE-798).
  const token = jwt.sign({ username, digest }, config.jwtSecret);
  res.json({ token });
});

router.post('/reset', (req, res) => {
  // CWE-330: reset token from Math.random.
  res.json({ token: resetToken() });
});

// CWE-1321: prototype pollution via unsafe recursive merge.
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      target[key] = target[key] || {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

router.post('/preferences', (req, res) => {
  // SOURCE (CWE-1321): user JSON merged into an object; __proto__ pollutes.
  const prefs = merge({}, req.body);
  res.json({ saved: Object.keys(prefs) });
});

module.exports = router;

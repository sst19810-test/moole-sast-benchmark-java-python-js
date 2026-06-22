'use strict';

const express = require('express');
const userService = require('../services/userService');

const router = express.Router();

// SOURCE (CWE-89): req.query.id -> userService.getUserById -> db.runQuery
router.get('/lookup', (req, res) => {
  userService.getUserById(req.query.id, (err, rows) => {
    if (err) return res.status(500).json({ error: String(err) });
    res.json(rows);
  });
});

// SOURCE (CWE-89): req.query.q flows cross-file into the LIKE sink.
router.get('/search', (req, res) => {
  userService.searchUsers(req.query.q, (err, rows) => {
    if (err) return res.status(500).json({ error: String(err) });
    res.json(rows);
  });
});

module.exports = router;

'use strict';

const express = require('express');
const serialize = require('node-serialize');
const commandService = require('../services/commandService');

const router = express.Router();

// SOURCE (CWE-78): req.query.folder -> commandService.archiveFolder -> exec
router.get('/archive', (req, res) => {
  commandService.archiveFolder(req.query.folder, (err) => {
    if (err) return res.status(500).json({ error: String(err) });
    res.json({ status: 'ok' });
  });
});

// SOURCE (CWE-22): req.query.name -> commandService.readReport -> fs.readFile
router.get('/report', (req, res) => {
  commandService.readReport(req.query.name, (err, data) => {
    if (err) return res.status(404).json({ error: 'not found' });
    res.type('text/plain').send(data);
  });
});

// SOURCE (CWE-918): fully user-controlled URL fetched server-side.
router.get('/proxy', async (req, res) => {
  try {
    const data = await commandService.fetchUrl(req.query.url);
    res.send(data);
  } catch (e) {
    res.status(502).json({ error: String(e) });
  }
});

// SOURCE (CWE-502): node-serialize.unserialize on attacker-controlled body.
router.post('/session', (req, res) => {
  const obj = serialize.unserialize(req.body.payload);
  res.json({ loaded: typeof obj });
});

module.exports = router;

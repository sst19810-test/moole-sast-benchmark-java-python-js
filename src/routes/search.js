'use strict';

const express = require('express');
const { MongoClient } = require('mongodb');
const config = require('../config');

const router = express.Router();

// SINK (CWE-79): reflected XSS — query echoed into HTML without escaping.
router.get('/echo', (req, res) => {
  const q = req.query.q || '';
  res.type('text/html').send('<html><body>You searched: ' + q + '</body></html>');
});

// SINK (CWE-95): eval over a user-supplied expression.
router.get('/calc', (req, res) => {
  const expr = req.query.expr || '0';
  // eslint-disable-next-line no-eval
  const result = eval(expr);
  res.json({ result });
});

// SINK (CWE-601): open redirect — Location header from user input.
router.get('/go', (req, res) => {
  res.redirect(req.query.next);
});

// SINK (CWE-943): NoSQL injection — request object used directly as a filter.
router.post('/find', async (req, res) => {
  const client = new MongoClient(config.mongoUrl);
  try {
    await client.connect();
    const col = client.db('app').collection('users');
    // req.body.filter may contain operators like {$ne: null} / {$gt: ''}.
    const docs = await col.find(req.body.filter).toArray();
    res.json(docs);
  } finally {
    await client.close();
  }
});

module.exports = router;

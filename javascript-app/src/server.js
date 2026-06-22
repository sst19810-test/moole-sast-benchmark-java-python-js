'use strict';

const express = require('express');
const config = require('./config');

const usersRoute = require('./routes/users');
const filesRoute = require('./routes/files');
const searchRoute = require('./routes/search');
const authRoute = require('./routes/auth');

const app = express();
app.use(express.json());

app.use('/users', usersRoute);
app.use('/files', filesRoute);
app.use('/search', searchRoute);
app.use('/auth', authRoute);

app.get('/health', (req, res) => res.json({ status: 'ok' }));

// CWE-1333: ReDoS — catastrophic backtracking regex over user input.
app.get('/validate', (req, res) => {
  const input = req.query.value || '';
  const re = /^(a+)+$/;
  res.json({ valid: re.test(input) });
});

app.listen(config.port, () => {
  // eslint-disable-next-line no-console
  console.log(`vulnapp listening on ${config.port}`);
});

module.exports = app;

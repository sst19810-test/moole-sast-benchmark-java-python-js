'use strict';

const mysql = require('mysql');
const config = require('./config');

// Connection uses the hardcoded password from config (CWE-798 origin).
const connection = mysql.createConnection({
  host: '10.10.60.12',
  user: 'app',
  password: config.dbPassword,
  database: 'app',
});

/**
 * SINK (CWE-89): executes an already-assembled SQL string. Callers build the
 * string by concatenating request data, so this is the terminal SQL sink.
 */
function runQuery(sql, cb) {
  connection.query(sql, cb);
}

/**
 * Control sample: parameterized query with placeholders (NOT a finding).
 */
function runQuerySafe(sql, params, cb) {
  connection.query(sql, params, cb);
}

module.exports = { runQuery, runQuerySafe };

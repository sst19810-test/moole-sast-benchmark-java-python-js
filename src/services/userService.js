'use strict';

const db = require('../db');

/**
 * Forwards tainted request data from the routes into the SQL sink in db.js,
 * forming a cross-file taint flow:
 * routes/users.js -> services/userService.js -> db.runQuery
 */

// CWE-89: id concatenated directly into the query string.
function getUserById(id, cb) {
  const sql = 'SELECT id, username, email FROM users WHERE id = ' + id;
  db.runQuery(sql, cb);
}

// CWE-89: template literal builds a LIKE filter from user input.
function searchUsers(term, cb) {
  const sql = `SELECT id, username FROM users WHERE username LIKE '%${term}%'`;
  db.runQuery(sql, cb);
}

// Control sample: parameterized (should NOT be flagged).
function getUserSafe(id, cb) {
  db.runQuerySafe('SELECT id, username FROM users WHERE id = ?', [id], cb);
}

module.exports = { getUserById, searchUsers, getUserSafe };

'use strict';

const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

/**
 * OS / filesystem / network helpers. Command, path, and SSRF sinks live here.
 */

// SINK (CWE-78): user input interpolated into a shell command string.
function archiveFolder(folder, cb) {
  exec('tar -czf /tmp/archive.tgz ' + folder, cb);
}

// SINK (CWE-22): user path joined under a base directory then read.
function readReport(name, cb) {
  const full = path.join('/var/app/reports', name);
  fs.readFile(full, 'utf8', cb);
}

// SINK (CWE-918): server-side request to a fully user-controlled URL.
async function fetchUrl(url) {
  const res = await axios.get(url);
  return res.data;
}

// Control sample: fixed host, only a path segment is appended (NOT a finding).
async function fetchInternal(p) {
  const res = await axios.get('https://api.internal.example.com/v1/' + encodeURIComponent(p));
  return res.data;
}

module.exports = { archiveFolder, readReport, fetchUrl, fetchInternal };

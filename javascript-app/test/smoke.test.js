'use strict';

const test = require('node:test');
const assert = require('node:assert');

// Smoke test placeholder (not a security test). Requires deps installed.
test('config module loads', () => {
  const config = require('../src/config');
  assert.ok(config.port);
});

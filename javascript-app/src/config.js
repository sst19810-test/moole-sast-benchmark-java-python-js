'use strict';

// WARNING: secrets intentionally hardcoded in source for SAST testing.
module.exports = {
  // CWE-798: hardcoded credentials / secrets.
  jwtSecret: 'sup3r-s3cret-jwt-key-do-not-commit',
  dbPassword: 'r00tP@ssw0rd',
  apiKey: 'sk_live_51HxhardcodedStripeKeyAABBCCDDEEFF',
  awsSecret: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',

  // Control sample: read from environment (should NOT be flagged).
  mongoUrl: process.env.MONGO_URL || 'mongodb://localhost:27017',
  port: process.env.PORT || 3000,
};

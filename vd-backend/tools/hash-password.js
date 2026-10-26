'use strict';
// Usage: npm run hash -- "your long password"   (prints an argon2id hash to put in .env)
const argon2 = require('argon2');
const pw = process.argv[2];
if (!pw || pw.length < 12) { console.error('Use a password of at least 12 characters (a long phrase is best).'); process.exit(1); }
argon2.hash(pw, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 }).then(h => console.log(h));

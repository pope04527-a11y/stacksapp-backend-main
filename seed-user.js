// seed-user.js
// Inserts one test user directly into the SQLite-backed "users" table used by the shim.
// Usage: node seed-user.js

const path = require('path');
const { EJSON } = require('bson');
const Database = require('better-sqlite3');
const fs = require('fs');

const SQLITE_FILE = process.env.SQLITE_FILE || path.join(__dirname, 'data.sqlite');

function ensureTable(db, name) {
  const row = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name = ?").get(name);
  if (!row) db.prepare(`CREATE TABLE IF NOT EXISTS "${name}" (_id TEXT PRIMARY KEY, doc TEXT)`).run();
}

try {
  // create file if missing
  if (!fs.existsSync(SQLITE_FILE)) {
    fs.closeSync(fs.openSync(SQLITE_FILE, 'w'));
    console.log('Created sqlite file:', SQLITE_FILE);
  }

  const db = new Database(SQLITE_FILE);
  ensureTable(db, 'users');

  // Adjust these credentials as you like
  const username = 'testuser';
  const phone = '07000000001';
  const password = 'password'; // loginPassword
  const inviteCode = 'INITCODE';

  // _id must be a string; keep it numeric-ish or timestamp to match earlier shim behavior
  const _id = String(Date.now());

  const user = {
    _id,
    username: username,
    phone: phone,
    loginPassword: password,
    withdrawPassword: password,
    gender: 'Male',
    inviteCode: inviteCode,
    referredBy: '',
    vipLevel: 1,
    balance: 1000,
    commission: 0,
    commissionToday: 0,
    lastCommissionReset: '',
    token: '', // will be set during login
    suspended: false,
    currentSet: 1,
    setStartingBalance: null,
    createdAt: new Date().toISOString()
  };

  const stmt = db.prepare(`INSERT OR REPLACE INTO "users" (_id, doc) VALUES (?, ?)`);
  stmt.run(_id, EJSON.stringify(user));

  console.log('✅ Seeded user:', { username, phone, password, inviteCode });
  db.close();
} catch (err) {
  console.error('❌ Failed to seed user:', err && err.message ? err.message : err);
  process.exit(1);
}
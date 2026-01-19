#!/usr/bin/env node
// Usage: node export-sqlite-to-json.js data.sqlite outDir
// Example: node export-sqlite-to-json.js data.sqlite ./data

const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { EJSON } = require('bson');

if (process.argv.length < 4) {
  console.error('Usage: node export-sqlite-to-json.js <sqlite-file> <out-dir>');
  process.exit(1);
}

const SQLITE = process.argv[2];
const OUTDIR = process.argv[3];

if (!fs.existsSync(SQLITE)) {
  console.error('SQLite file not found:', SQLITE);
  process.exit(1);
}
if (!fs.existsSync(OUTDIR)) fs.mkdirSync(OUTDIR, { recursive: true });

const db = new Database(SQLITE, { readonly: true });

const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';").all();

for (const row of tables) {
  const name = row.name;
  console.log('Exporting', name);
  const rows = db.prepare(`SELECT doc FROM "${name}";`).all();
  const docs = rows.map(r => {
    try {
      return EJSON.parse(r.doc);
    } catch (e) {
      try { return JSON.parse(r.doc); } catch (e2) { return r.doc; }
    }
  });
  const outPath = path.join(OUTDIR, `${name}.json`);
  fs.writeFileSync(outPath, EJSON.stringify(docs, null, 2), 'utf8');
  console.log(' ->', outPath);
}

db.close();
console.log('Export complete.');
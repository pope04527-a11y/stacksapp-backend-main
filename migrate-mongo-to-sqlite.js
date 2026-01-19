#!/usr/bin/env node
// Usage:
//   node migrate-mongo-to-sqlite.js "<MONGO_URI>" "<DB_NAME>" "out.sqlite" upsert
// Example:
//   node migrate-mongo-to-sqlite.js "mongodb+srv://Mark:Mark075555@stacks1.evo4zih.mongodb.net/?retryWrites=true&w=majority&appName=Stacks1" test data.sqlite upsert

const { MongoClient } = require('mongodb');
const { EJSON } = require('bson');
const Database = require('better-sqlite3');

if (process.argv.length < 6) {
  console.error('Usage: node migrate-mongo-to-sqlite.js "<MONGO_URI>" "<DB_NAME>" "out.sqlite" upsert');
  process.exit(1);
}

const MONGO_URI = process.argv[2];
const DB_NAME = process.argv[3];
const SQLITE_FILE = process.argv[4];
const MODE = (process.argv[5] || 'upsert').toLowerCase();

async function run() {
  // create client without deprecated options
  const client = new MongoClient(MONGO_URI);
  await client.connect();

  const db = client.db(DB_NAME);
  console.log('Connected to MongoDB DB:', DB_NAME);

  const sqlite = new Database(SQLITE_FILE);
  sqlite.pragma('journal_mode = WAL');

  const collections = await db.listCollections().toArray();
  if (collections.length === 0) {
    console.log('No collections found in DB.');
  }

  for (const collInfo of collections) {
    const name = collInfo.name;
    console.log(`\nProcessing collection: ${name}`);

    sqlite.prepare(`CREATE TABLE IF NOT EXISTS "${name}" (_id TEXT PRIMARY KEY, doc TEXT)`).run();

    const insertSql = MODE === 'upsert'
      ? `INSERT INTO "${name}" (_id, doc) VALUES (?, ?) ON CONFLICT(_id) DO UPDATE SET doc = excluded.doc`
      : `INSERT OR IGNORE INTO "${name}" (_id, doc) VALUES (?, ?)`;

    const insertStmt = sqlite.prepare(insertSql);

    const cursor = db.collection(name).find({});
    const BATCH_SIZE = 500;
    let batch = [];
    let processed = 0;

    for await (const rawDoc of cursor) {
      const doc = rawDoc;
      const id = doc && doc._id ? String(doc._id) : null;
      if (doc && doc._id) doc._id = id;
      const json = EJSON.stringify(doc);
      batch.push({ id, json });

      if (batch.length >= BATCH_SIZE) {
        const insertMany = sqlite.transaction((rows) => {
          for (const r of rows) insertStmt.run(r.id, r.json);
        });
        insertMany(batch);
        processed += batch.length;
        process.stdout.write(`\rProcessed ${processed} documents for ${name}`);
        batch = [];
      }
    }

    if (batch.length > 0) {
      const insertMany = sqlite.transaction((rows) => {
        for (const r of rows) insertStmt.run(r.id, r.json);
      });
      insertMany(batch);
      processed += batch.length;
      process.stdout.write(`\rProcessed ${processed} documents for ${name}`);
    }

    console.log(`\nFinished ${name}: processed ${processed} documents`);
  }

  sqlite.close();
  await client.close();
  console.log('\nMigration complete. SQLite file:', SQLITE_FILE);
}

run().catch(err => {
  console.error('Migration error:', err);
  process.exit(1);
});
#!/usr/bin/env node
// index.js - MongoDB-enabled (Mongo connection string in-file as requested).

const path = require('path');
const fs = require('fs');

const mongoose = require('mongoose');
// Disable mongoose command buffering so any accidental native driver calls fail fast.
mongoose.set('bufferCommands', false);

const express = require('express');
const cors = require('cors');
const pathModule = require('path');
require('dotenv').config();

const { EJSON } = require('bson');
const cookieParser = require('cookie-parser');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS: allow credentials so cookie-based auth works when needed
app.use(cors({ origin: true, credentials: true }));

// parse cookies so handlers/middleware can read httpOnly cookie
app.use(cookieParser());

// Health endpoint fallback
try {
  app.get('/health', require('./src/health'));
} catch (e) {
  app.get('/health', (req, res) => res.json({ ok: true }));
}

// -----------------------------
// NOTE: Serve production frontend from dist (Vite default)
// -----------------------------
const clientDir = pathModule.join(__dirname, 'dist');
// Serve static files from dist (index.html + assets)
app.use(express.static(clientDir));

// -----------------------------
// EJSON parse/stringify helpers
// -----------------------------
function parseStoredDoc(docStr) {
  if (docStr === null || docStr === undefined) return null;
  try { return EJSON.parse(docStr); } catch (e) {
    try { return JSON.parse(docStr); } catch (e2) { return docStr; }
  }
}
function stringifyDoc(doc) {
  try { return EJSON.stringify(doc); } catch (e) { return JSON.stringify(doc); }
}

// -----------------------------
// safeHydrate helper
// -----------------------------
function safeHydrate(model, doc) {
  if (!doc) return null;
  if (typeof model.hydrate === 'function') {
    try {
      return model.hydrate(doc);
    } catch (e) {
      const inst = new model();
      try { Object.assign(inst, doc); } catch (e2) {}
      return inst;
    }
  }
  const inst = new model();
  try { Object.assign(inst, doc); } catch (e) {}
  return inst;
}

// -----------------------------
// Compatibility: allow string ids in ObjectId.isValid checks
// -----------------------------
try {
  if (mongoose && mongoose.Types && mongoose.Types.ObjectId) {
    const originalIsValid = mongoose.Types.ObjectId.isValid.bind(mongoose.Types.ObjectId);
    mongoose.Types.ObjectId.isValid = function (v) {
      if (typeof v === 'string' && v.length > 0) return true;
      try { return originalIsValid(v); } catch (e) { return false; }
    };
  }
} catch (e) {
  // ignore
}

// -----------------------------
// MongoDB connection (hardcoded)
// -----------------------------
// Replace the DB name at the end of the URI if you want a different default database.
// WARNING: credentials are embedded in this file as requested.
const MONGODB_URI = 'mongodb+srv://Sequence:Mark075555@opts.ix4lknk.mongodb.net/mydb?retryWrites=true&w=majority';

if (!MONGODB_URI) {
  console.error('❌ MONGODB_URI is not set. Please update the connection string in this file.');
  process.exit(1);
}

const mongooseOptions = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
};

mongoose.connect(MONGODB_URI, mongooseOptions)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => {
    console.error('❌ MongoDB connection error:', err && err.message ? err.message : err);
    process.exit(1);
  });

mongoose.connection.on('error', err => {
  console.error('MongoDB connection error:', err);
});

// -----------------------------
// Mount routes AFTER mongoose connection is attempted
// -----------------------------
try {
  const apiRouter = require("./routes/api");
  app.use("/api", apiRouter);
} catch (e) {
  console.error('Failed to mount /api routes:', e && e.message ? e.message : e);
}
try {
  const adminRouter = require("./routes/admin");
  app.use("/admin", adminRouter);
} catch (e) {
  console.error('Failed to mount /admin routes:', e && e.message ? e.message : e);
}
try {
  const processCommissionsRouter = require("./routes/process-commission");
  app.use(processCommissionsRouter);
} catch (e) {
  console.error('Failed to mount process-commission route:', e && e.message ? e.message : e);
}
try {
  const uploadRouter = require("./routes/upload");
  app.use("/api", uploadRouter);
} catch (e) {
  // optional
}

// -----------------------------
// SPA fallback for client-side routes (serve dist/index.html)
// -----------------------------
// IMPORTANT: This must come AFTER your API routes so API calls are not hijacked.
app.get('*', (req, res, next) => {
  if (req.method !== 'GET') return next();
  const accept = req.headers.accept || '';
  if (!accept.includes('text/html')) return next();
  const indexPath = pathModule.join(clientDir, 'index.html');
  res.sendFile(indexPath, err => {
    if (err) next(err);
  });
});

// 404 + error handler (for non-HTML/API requests)
app.use((req, res) => res.status(404).json({ success: false, message: 'Resource not found' }));
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err && err.stack ? err.stack : err);
  res.status(500).json({ success: false, message: 'Internal server error', error: err && err.message ? err.message : String(err) });
});

// Cron (uses mongoose models)
const cron = require('node-cron');
function getTodayDateString() { return new Date().toISOString().slice(0,10); }
cron.schedule('0 0 * * *', async () => {
  try {
    const UserForCron = mongoose.models && mongoose.models.User ? mongoose.models.User : null;
    const today = getTodayDateString();
    if (UserForCron) {
      await UserForCron.updateMany({}, { $set: { commissionToday: 0, lastCommissionReset: today } });
      console.log('✅ Reset commissionToday for all users at midnight', today);
    } else {
      console.warn('Cron cannot run: User model missing.');
    }
  } catch (err) {
    console.error('Cron error:', err && err.message ? err.message : err);
  }
});

// Start
const PORT = process.env.PORT || 3002;
app.listen(PORT, () => console.log(`✅ Backend running at http://localhost:${PORT}`));

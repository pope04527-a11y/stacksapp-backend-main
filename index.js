#!/usr/bin/env node
// index.js - MongoDB-enabled (Mongo connection string in-file as requested).

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

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

// Serve static files
app.use("/assets", express.static(pathModule.join(__dirname, "public", "assets")));
app.use("/favicon.ico", express.static(pathModule.join(__dirname, "public", "favicon.ico")));
app.use("/admin-panel", express.static(pathModule.join(__dirname, "public", "admin-panel")));
app.use("/", express.static(pathModule.join(__dirname, "public")));

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
/*
  Important: previously a failing require("./routes/api") would be swallowed by a small
  catch and the server would continue running without /api routes mounted, causing
  clients to receive generic 404 {"success":false,"message":"Resource not found"}.
  The logic below improves logging and, if mounting /routes/api fails, provides a
  minimal fallback router which exposes a simple GET /api/ and a POST /api/login
  that attempts to authenticate users directly using the 'users' collection so the
  login flow still works even if the full routes file couldn't be loaded.
*/

try {
  console.log('⏳ Attempting to require and mount ./routes/api');
  const apiRouter = require("./routes/api");
  app.use("/api", apiRouter);
  console.log('✅ Mounted /api routes');
} catch (e) {
  // Print full stack to logs so deployments clearly show the root cause.
  console.error('❌ Failed to mount /api routes:', e && e.stack ? e.stack : e);

  // Fallback: provide a minimal router with a sanity GET and a lightweight POST /login
  // that authenticates against the same users collection. This helps keep login working
  // even if the full routes file failed to load (so frontend doesn't get silent 404).
  const fallbackApi = express.Router();

  fallbackApi.get('/', (req, res) => {
    res.status(503).json({
      success: false,
      message: 'API routes failed to load on startup. Minimal fallback active. Check server logs for the original error.'
    });
  });

  // Minimal login endpoint — mirrors the behavior of routes/api.js login handler,
  // but avoids calling `user.save()` to prevent DocumentNotFoundError when _id types
  // don't match the Mongoose model's expectation. We update the token via the
  // native MongoDB collection API to avoid Mongoose casting.
  fallbackApi.post('/login', async (req, res) => {
    try {
      const input = req.body.input || req.body.username || "";
      const password = req.body.password;

      if (!input || password === undefined) {
        return res.status(400).json({ success: false, message: 'Missing credentials' });
      }

      // Minimal User model bound to the same 'users' collection (non-strict schema)
      const User = mongoose.models.User || mongoose.model('User', new mongoose.Schema({}, { collection: 'users', strict: false }));

      const user = await User.findOne({
        $or: [{ username: input }, { phone: input }],
        loginPassword: password
      }).lean ? await User.findOne({ $or: [{ username: input }, { phone: input }], loginPassword: password }) : await User.findOne({ $or: [{ username: input }, { phone: input }], loginPassword: password });

      if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });

      if (user.suspended) return res.status(403).json({ success: false, message: 'Account suspended' });

      // Generate token and update via native driver to avoid Mongoose _id casting problems
      const newToken = crypto.randomBytes(24).toString('hex');

      try {
        // Try updating using the raw collection with the exact _id value we received.
        // This avoids Mongoose casting _id to ObjectId which can fail when documents
        // actually use string _id values.
        const coll = mongoose.connection.db.collection('users');
        let updateResult = await coll.updateOne(
          { _id: user._id },
          { $set: { token: newToken } }
        );

        // If no match (possible type mismatch), attempt a string-cast of _id as a fallback.
        if (updateResult.matchedCount === 0) {
          updateResult = await coll.updateOne(
            { _id: String(user._id) },
            { $set: { token: newToken } }
          );
        }

        // If still no match, attempt to update by username as a last resort (shouldn't be necessary)
        if (updateResult.matchedCount === 0 && user.username) {
          updateResult = await coll.updateOne(
            { username: user.username },
            { $set: { token: newToken } }
          );
        }

        // reflect token in returned user object (don't rely on user.save())
        user.token = newToken;
      } catch (err) {
        console.error('Fallback native update token error:', err && err.stack ? err.stack : err);
        // still return success? better to surface error
        return res.status(500).json({ success: false, message: 'Failed to update token', error: err && err.message ? err.message : String(err) });
      }

      // Return the user object (same shape as main route)
      return res.json({ success: true, user });
    } catch (err) {
      console.error('Fallback /api/login error:', err && err.stack ? err.stack : err);
      return res.status(500).json({ success: false, message: 'Login failed (fallback)', error: err && err.message ? err.message : String(err) });
    }
  });

  app.use('/api', fallbackApi);
}

try {
  const adminRouter = require("./routes/admin");
  app.use("/admin", adminRouter);
} catch (e) {
  console.error('Failed to mount /admin routes:', e && e.stack ? e.stack : e);
}
try {
  const processCommissionsRouter = require("./routes/process-commission");
  app.use(processCommissionsRouter);
} catch (e) {
  console.error('Failed to mount process-commission route:', e && e.stack ? e.stack : e);
}
try {
  const uploadRouter = require("./routes/upload");
  app.use("/api", uploadRouter);
} catch (e) {
  // optional
  console.error('Failed to mount upload route (optional):', e && e.stack ? e.stack : e);
}

// 404 + error handler
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

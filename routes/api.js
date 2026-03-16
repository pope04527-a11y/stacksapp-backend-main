const express = require('express');
const crypto = require('crypto');
const mongoose = require('mongoose');
const cloudinary = require('cloudinary').v2;
const axios = require('axios');

const { distributeReferralCommission } = require('./commissionService');

const router = express.Router();

// New: IP + geo helpers and event model
const getClientIp = require('../server/utils/getClientIp'); // adjusted path to new utils
const { geoLookup } = require('../server/utils/geoLookup');
const LoginEvent = require('../server/models/LoginEvent');

// ========== MODELS WITH EXPLICIT SCHEMA ==========
const userSchema = new mongoose.Schema({
  _id: String, // allow string IDs (we store timestamp/string ids in SQLite)
  username: String,
  phone: String,
  loginPassword: String,
  withdrawPassword: String,
  walletAddress: String,
  exchange: String,
  gender: String,
  balance: { type: Number, default: 0 },
  commission: { type: Number, default: 0 },
  commissionToday: { type: Number, default: 0 },
  lastCommissionReset: { type: String, default: "" }, // <-- Added for midnight reset tracking
  vipLevel: { type: Number, default: 1 },
  inviteCode: String,
  referredBy: String,
  token: { type: String, default: "" },
  suspended: { type: Boolean, default: false },
  currentSet: { type: Number, default: 1 },
  // store starting balance for current set so we can enforce min-product-price rule
  setStartingBalance: { type: Number, default: null },
  createdAt: String,

  // New fields for cross-device sign-in and working-day recording
  // registeredWorkingDays: map { "YYYY-MM-DD": numberOfSetsCompleted }
  registeredWorkingDays: { type: mongoose.Schema.Types.Mixed, default: {} },
  // signState: { signedCount: Number, lastSignDate: "YYYY-MM-DD" }
  signState: { type: mongoose.Schema.Types.Mixed, default: { signedCount: 0, lastSignDate: null } },

  // Manual reset flag: user requests reset for next set (must be processed by admin or via explicit endpoint)
  resetRequested: { type: Boolean, default: false }
}, { collection: 'users', strict: false });

const User = mongoose.models.User || mongoose.model('User', userSchema);
const Task = mongoose.models.Task || mongoose.model('Task', new mongoose.Schema({}, { collection: 'tasks', strict: false }));
const Combo = mongoose.models.Combo || mongoose.model('Combo', new mongoose.Schema({}, { collection: 'combos', strict: false }));
const Log = mongoose.models.Log || mongoose.model('Log', new mongoose.Schema({}, { collection: 'logs', strict: false }));
const Deposit = mongoose.models.Deposit || mongoose.model('Deposit', new mongoose.Schema({}, { collection: 'deposits', strict: false }));
const Withdrawal = mongoose.models.Withdrawal || mongoose.model('Withdrawal', new mongoose.Schema({}, { collection: 'withdrawals', strict: false }));
const Notification = mongoose.models.Notification || mongoose.model('Notification', new mongoose.Schema({}, { collection: 'notifications', strict: false }));
const Transaction = mongoose.models.Transaction || mongoose.model('Transaction', new mongoose.Schema({}, { collection: 'transactions', strict: false }));
const LinkClick = mongoose.models.LinkClick || mongoose.model('LinkClick', new mongoose.Schema({}, { collection: 'linkclicks', strict: false }));
const Setting = mongoose.models.Setting || mongoose.model('Setting', new mongoose.Schema({}, { collection: 'settings', strict: false }));

// --- Session model to support multiple concurrent logins per user (one session per device/login) ---
const sessionSchema = new mongoose.Schema({
  token: { type: String, index: true },
  userId: String,
  userAgent: String,
  ip: String,
  createdAt: { type: String, default: () => new Date().toISOString() },
  lastUsedAt: { type: String, default: null },
  expiresAt: { type: String, default: null }, // optional ISO string
  revoked: { type: Boolean, default: false }
}, { collection: 'sessions', strict: false });

const Session = mongoose.models.Session || mongoose.model('Session', sessionSchema);

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME || 'dycytqdfj',
    api_key: process.env.CLOUDINARY_API_KEY || '983286743251596',
    api_secret: process.env.CLOUDINARY_API_SECRET || 'zeU4nedVzVzvqqndh2MF82AdRiI',
    secure: true
});

// ========== Product cache & helpers (pre-warm + in-flight dedupe + periodic refresh) ==========
const CLOUDINARY_CACHE_DURATION = 1000 * 60 * 5; // 5 minutes
let cachedProducts = [];
let lastCloudinaryFetch = 0;
let cloudinaryFetchInFlight = null; // promise for dedupe

// Helper: extract price using multiple heuristics (context, tags, public_id)
function extractPriceFromResource(r) {
  if (!r) return undefined;

  // 1) context.custom.price preferred
  if (r.context && r.context.custom && typeof r.context.custom.price !== 'undefined' && r.context.custom.price !== 'N/A') {
    const p = parseFloat(String(r.context.custom.price).replace(/[^\d.]/g, ''));
    if (!Number.isNaN(p)) return p;
  }

  // 2) tags like price_123 or price-123
  if (Array.isArray(r.tags) && r.tags.length) {
    for (const t of r.tags) {
      if (!t) continue;
      const mTag = String(t).match(/^price[_-]?(\d+(?:\.\d+)?)$/i);
      if (mTag) {
        const p = parseFloat(mTag[1]);
        if (!Number.isNaN(p)) return p;
      }
    }
  }

  // 3) trailing-numeric-tokens heuristic on public_id
  if (typeof r.public_id === 'string') {
    const parts = r.public_id.split('_').filter(Boolean);
    const trailing = [];
    for (let i = parts.length - 1; i >= 0; i--) {
      const t = parts[i];
      if (/^\d+$/.test(t)) {
        trailing.unshift(t);
        if (trailing.length >= 3) break;
      } else break;
    }
    if (trailing.length >= 2) {
      const intPart = trailing[trailing.length - 2];
      const fracPart = trailing[trailing.length - 1];
      const cand = parseFloat(`${intPart}.${fracPart}`);
      if (!Number.isNaN(cand)) return cand;
    } else if (trailing.length === 1) {
      const cand = parseFloat(trailing[0]);
      if (!Number.isNaN(cand)) return cand;
    }

    // fallback: longest numeric token anywhere
    const tokens = (r.public_id.match(/\d+/g) || []).map(s => s.replace(/^0+/, '') || '0');
    if (tokens.length) {
      tokens.sort((a, b) => {
        if (b.length !== a.length) return b.length - a.length;
        return Number(b) - Number(a);
      });
      const cand = parseFloat(tokens[0]);
      if (!Number.isNaN(cand)) return cand;
    }
  }

  return undefined;
}

// Helper: generate a random price between min and max (two decimals)
function generateRandomPrice(min = 10, max = 100) {
  const lo = Number(min) || 10;
  const hi = Number(max) || 100;
  const v = Math.random() * (hi - lo) + lo;
  return Math.round((v + Number.EPSILON) * 100) / 100;
}

async function fetchProductsFromCloudinary() {
  if (cloudinaryFetchInFlight) return cloudinaryFetchInFlight;

  cloudinaryFetchInFlight = (async () => {
    const prefixEnv = (process.env.CLOUDINARY_PRODUCTS_PREFIX || 'products/').toString();
    let products = [];
    let next_cursor = undefined;

    try {
      do {
        const opts = {
          type: 'upload',
          max_results: 500,
          context: true,
          tags: true,
          ...(next_cursor ? { next_cursor } : {})
        };
        if (prefixEnv) opts.prefix = prefixEnv;

        const result = await cloudinary.api.resources(opts);
        const pageProducts = (result.resources || []).map(r => {
          const name = (r.context && r.context.custom && (r.context.custom.caption || r.context.custom.name))
            || r.filename
            || (typeof r.public_id === 'string' ? r.public_id.split('/').pop() : r.public_id);

          const description = (r.context && r.context.custom && (r.context.custom.alt || r.context.custom.description)) || '';

          const price = extractPriceFromResource(r);
          const finalPrice = (typeof price === 'number' && !Number.isNaN(price)) ? Number(price) : undefined;

          return {
            image: r.secure_url,
            name,
            price: finalPrice,
            description,
            public_id: r.public_id
          };
        }).filter(p => p.image); // only keep items with url

        products = products.concat(pageProducts);
        next_cursor = result.next_cursor;
      } while (next_cursor);

      // Assign reasonable random prices to items lacking a numeric price
      const numericPrices = products.map(p => p.price).filter(v => typeof v === 'number' && !Number.isNaN(v));
      let median = 25;
      if (numericPrices.length) {
        numericPrices.sort((a, b) => a - b);
        median = numericPrices[Math.floor(numericPrices.length / 2)];
      }
      const randMin = Math.max(1, median * 0.5);
      const randMax = Math.max(randMin + 1, median * 1.5);

      let randomAssignedCount = 0;
      products = products.map(p => {
        if (typeof p.price !== 'number' || Number.isNaN(p.price)) {
          randomAssignedCount++;
          return { ...p, price: generateRandomPrice(randMin, randMax), _priceAssigned: 'random' };
        }
        return { ...p, _priceAssigned: 'extracted' };
      });

      cachedProducts = products;
      lastCloudinaryFetch = Date.now();

      console.log(`Cloudinary fetch: loaded ${cachedProducts.length} product(s) (prefix='${prefixEnv}'). numeric:${numericPrices.length}; randomAssigned:${randomAssignedCount}`);

      return cachedProducts;
    } finally {
      cloudinaryFetchInFlight = null;
    }
  })();

  return cloudinaryFetchInFlight;
}

/**
 * Returns cached products. If cache is empty it waits for initial fetch (caller will wait).
 * If cache is stale but non-empty, returns cached and triggers background refresh.
 */
async function getCachedCloudinaryProducts() {
  const now = Date.now();
  if (cachedProducts.length && (now - lastCloudinaryFetch < CLOUDINARY_CACHE_DURATION)) {
    return cachedProducts;
  }
  if (!cachedProducts.length) {
    try {
      return await fetchProductsFromCloudinary();
    } catch (err) {
      console.warn('Cloudinary initial fetch failed:', err && err.message ? err.message : err);
      return cachedProducts || [];
    }
  }
  // stale but present -> refresh in background
  fetchProductsFromCloudinary().catch(err => {
    console.warn('Cloudinary background refresh failed:', err && err.message ? err.message : err);
  });
  return cachedProducts;
}

/**
 * Waits up to timeoutMs for an initial fetch; if timeout triggers returns cachedProducts (may be empty).
 * Useful to avoid blocking start-task too long if Cloudinary is temporarily slow.
 */
async function getCachedCloudinaryProductsWithTimeout(timeoutMs = 800) {
  const now = Date.now();
  if (cachedProducts.length && (now - lastCloudinaryFetch < CLOUDINARY_CACHE_DURATION)) {
    return cachedProducts;
  }
  try {
    const fetchPromise = getCachedCloudinaryProducts();
    const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error('cloudinary_timeout')), timeoutMs));
    return await Promise.race([fetchPromise, timeout]);
  } catch (err) {
    // on timeout or error return whatever cached we have (maybe empty)
    return cachedProducts || [];
  }
}

// Pre-warm cache on startup (best-effort, non-blocking)
setImmediate(() => {
  fetchProductsFromCloudinary()
    .then(() => console.log('Cloudinary cache pre-warmed, items:', cachedProducts.length))
    .catch(err => console.warn('Cloudinary pre-warm failed:', err && err.message ? err.message : err));
});

// Periodic refresh
setInterval(() => {
  fetchProductsFromCloudinary().catch(err => {
    console.warn('Periodic Cloudinary refresh failed:', err && err.message ? err.message : err);
  });
}, CLOUDINARY_CACHE_DURATION);
// ========== Utility & config ==========
const MIN_STARTING_CAPITAL_PERCENT = 0.30; // 30%

function generateInviteCode() {
    const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const digits = '0123456789';
    let letterCount = Math.random() < 0.5 ? 2 : 3;
    let digitCount = 6 - letterCount;
    let codeArr = [];
    for (let i = 0; i < letterCount; i++) {
        codeArr.push(letters.charAt(Math.floor(Math.random() * letters.length)));
    }
    for (let i = 0; i < digitCount; i++) {
        codeArr.push(digits.charAt(Math.floor(Math.random() * digits.length)));
    }
    for (let i = codeArr.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [codeArr[i], codeArr[j]] = [codeArr[j], codeArr[i]];
    }
    return codeArr.join('');
}

const vipRules = {
    1: { tasks: 40, commissionRate: 0.005, combinedProfit: 0.03, activation: 100, setsPerDay: 3 },
    2: { tasks: 45, commissionRate: 0.01, combinedProfit: 0.06, activation: 500, setsPerDay: 3 },
    3: { tasks: 50, commissionRate: 0.015, combinedProfit: 0.09, activation: 2000, setsPerDay: 3 },
    4: { tasks: 55, commissionRate: 0.02, combinedProfit: 0.12, activation: 5000, setsPerDay: 3 }
};

function hasPendingComboTask(tasks, user) {
    return tasks.some(t =>
        t.username === user.username &&
        t.isCombo &&
        (t.status === 'Pending' || t.status === 'pending')
    );
}

function hasPendingTask(tasks, user) {
    return tasks.some(t =>
        t.username === user.username &&
        !t.isCombo &&
        (t.status === 'Pending' || t.status === 'pending')
    );
}

// Helper: return "YYYY-MM-DD" for Europe/London timezone (server authoritative)
function getUKDateKey(d = new Date()) {
  try {
    const parts = new Intl.DateTimeFormat('en-GB', { timeZone: 'Europe/London' }).formatToParts(d);
    const y = parts.find(p => p.type === 'year')?.value;
    const m = parts.find(p => p.type === 'month')?.value;
    const day = parts.find(p => p.type === 'day')?.value;
    return `${y}-${String(m).padStart(2,'0')}-${String(day).padStart(2,'0')}`;
  } catch (err) {
    const dt = new Date(d);
    return `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2,'0')}-${String(dt.getDate()).padStart(2,'0')}`;
  }
}

// ========== Platform status helpers & middleware (NEW) ==========
function getUKHour() {
  try {
    const parts = new Intl.DateTimeFormat('en-GB', {
      timeZone: 'Europe/London',
      hour: '2-digit',
      hour12: false
    }).formatToParts(new Date());
    const hourPart = parts.find(p => p.type === 'hour');
    return parseInt(hourPart ? hourPart.value : new Date().toLocaleString('en-GB', { timeZone: 'Europe/London', hour12: false }).split(':')[0], 10);
  } catch (err) {
    return new Date().getUTCHours();
  }
}

async function getOrCreateSettings() {
  let settings = await Setting.findOne({});
  if (!settings) {
    settings = await Setting.create({
      platformClosed: false,
      autoOpenHourUK: 10,
      whoCanAccessDuringClose: [],
      service: { whatsapp: "", telegram: "" }
    });
  } else {
    const updates = {};
    if (typeof settings.platformClosed === 'undefined') updates.platformClosed = false;
    if (typeof settings.autoOpenHourUK === 'undefined') updates.autoOpenHourUK = 10;
    if (!Array.isArray(settings.whoCanAccessDuringClose)) updates.whoCanAccessDuringClose = [];
    if (!settings.service) updates.service = { whatsapp: "", telegram: "" };
    if (Object.keys(updates).length) {
      await Setting.updateOne({ _id: settings._id }, { $set: updates });
      settings = await Setting.findById(settings._id);
    }
  }
  return settings;
}

async function checkPlatformStatus(req, res, next) {
  try {
    const settings = await getOrCreateSettings();

    const ukHour = getUKHour();

    // Auto-open if hour is >= configured hour and platform currently closed
    if (settings.platformClosed && typeof settings.autoOpenHourUK === 'number' && !isNaN(settings.autoOpenHourUK)) {
      if (ukHour >= Number(settings.autoOpenHourUK)) {
        settings.platformClosed = false;
        await settings.save();
      }
    }

    // If still closed, check allowlist (normalize username + allowlist entries)
    if (settings.platformClosed) {
      const usernameRaw = req.user && req.user.username ? req.user.username : null;
      const username = usernameRaw ? usernameRaw.trim().toLowerCase() : null;

      if (!username || !Array.isArray(settings.whoCanAccessDuringClose) || !settings.whoCanAccessDuringClose.includes(username)) {
        return res.json({ success: false, message: "The system is temporarily closed. Tasks and withdrawals are disabled at the moment. Please try again later." });
      }
    }

    next();
  } catch (err) {
    console.error('checkPlatformStatus middleware error:', err && err.message ? err.message : err);
    next();
  }
}

// ========== Auth middleware (updated to support sessions) ==========
const verifyUserToken = async (req, res, next) => {
    try {
        // accept token from headers (x-auth-token) or Authorization Bearer
        // Extended: also accept token from cookies, request body, or query to be more tolerant of client setups.
        let rawHeader = req.headers['x-auth-token'] || req.headers['X-Auth-Token'] || req.headers['authorization'] || '';
        let token = null;

        // If header has "Bearer <token>" format
        if (rawHeader && typeof rawHeader === 'string' && rawHeader.trim().toLowerCase().startsWith('bearer ')) {
            token = String(rawHeader).trim().split(' ')[1];
        } else if (rawHeader && typeof rawHeader === 'string' && rawHeader.trim()) {
            // header might contain token directly (some clients set x-auth-token: <token>)
            token = String(rawHeader).trim();
        }

        // If no token yet, check cookies (if cookie-parser used)
        if (!token && req.cookies && req.cookies.token) {
            token = req.cookies.token;
        }

        // If still no token, try parsing Cookie header manually
        if (!token && req.headers && req.headers.cookie) {
            const cookieHeader = req.headers.cookie;
            const parts = cookieHeader.split(';').map(p => p.trim());
            for (const part of parts) {
                const [k, v] = part.split('=');
                if (!k) continue;
                if (k === 'token' || k === 'authToken' || k.toLowerCase() === 'token') {
                    token = decodeURIComponent(v || '').trim();
                    break;
                }
            }
        }

        // Also accept token from request body or query string (useful for some clients)
        if (!token && req.body && (req.body.token || req.body.authToken)) {
            token = req.body.token || req.body.authToken;
        }
        if (!token && req.query && (req.query.token || req.query.authToken)) {
            token = req.query.token || req.query.authToken;
        }

        // Also accept a custom header x-dev-username as previous dev fallback logic uses it
        const devUsernameFromBody = req.body && req.body.devUsername ? String(req.body.devUsername) : null;
        const devUsernameFromQuery = req.query && req.query.devUsername ? String(req.query.devUsername) : null;

        if (!token) {
            // Local dev fallback: allow requests from localhost when NODE_ENV !== 'production'
            if (process.env.NODE_ENV !== 'production' &&
                (req.hostname === 'localhost' || (req.headers.origin && req.headers.origin.includes('localhost')))) {
                try {
                    // Prefer dev username from body/query, else optional x-dev-username header, else first DB user
                    const devHeader = req.headers['x-dev-username'];
                    const devUsername = devUsernameFromBody || devUsernameFromQuery || (devHeader ? String(devHeader) : null);
                    let devUser = null;
                    if (devUsername) devUser = await User.findOne({ username: devUsername });
                    // fallback to first user in DB
                    if (!devUser) devUser = await User.findOne({});
                    if (devUser) {
                        req.user = devUser;
                        return next();
                    }
                    // No user in DB — continue to missing token response
                } catch (err) {
                    console.warn('Dev auth fallback error:', err && err.message ? err.message : err);
                }
            }
            return res.status(403).json({ success: false, message: 'Missing authentication token' });
        }

        // 1) Preferred flow: validate token via Session collection (supports multiple concurrent sessions)
        if (token) {
            const session = await Session.findOne({ token });
            if (session && !session.revoked) {
                // optional expiry check
                if (session.expiresAt && new Date(session.expiresAt) < new Date()) {
                    // expired
                    return res.status(403).json({ success: false, message: 'Session expired' });
                }
                const user = await User.findById(session.userId);
                if (!user) {
                    return res.status(403).json({ success: false, message: 'Invalid session (user not found)' });
                }
                // update lastUsedAt (best-effort)
                session.lastUsedAt = new Date().toISOString();
                try { await session.save(); } catch (e) { /* ignore save errors */ }
                req.user = user;
                req.session = session;
                return next();
            }
        }

        // 2) Backwards compatibility: legacy single-token stored on User.token
        const user = await User.findOne({ token });
        if (user) {
            req.user = user;
            // create an in-memory session placeholder for compatibility (not saved)
            req.session = {
              token: user.token,
              userId: user._id,
              createdAt: user.createdAt || new Date().toISOString(),
              legacy: true
            };
            return next();
        }

        // Local dev fallback on invalid token (unchanged)
        if (process.env.NODE_ENV !== 'production' &&
            (req.hostname === 'localhost' || (req.headers.origin && req.headers.origin.includes('localhost')))) {
            try {
                const devHeader = req.headers['x-dev-username'];
                const devUsername = devUsernameFromBody || devUsernameFromQuery || (devHeader ? String(devHeader) : null);
                let devUser = null;
                if (devUsername) devUser = await User.findOne({ username: devUsername });
                if (!devUser) devUser = await User.findOne({});
                if (devUser) {
                    req.user = devUser;
                    return next();
                }
            } catch (err) {
                console.warn('Dev auth fallback error (invalid token):', err && err.message ? err.message : err);
            }
        }

        return res.status(403).json({ success: false, message: 'Invalid or expired token' });
    } catch (err) {
        console.error('verifyUserToken error:', err && err.message ? err.message : err);
        return res.status(500).json({ success: false, message: 'Authentication error' });
    }
};

// ========== Endpoints ==========

// Settings
router.get('/settings', async (req, res) => {
    try {
        const settings = await getOrCreateSettings();

        // Normalize legacy withdrawFee -> withdrawFeePercent for clients
        let withdrawFeePercent = settings.withdrawFeePercent;
        if (typeof withdrawFeePercent === 'undefined' && typeof settings.withdrawFee !== 'undefined') {
          withdrawFeePercent = settings.withdrawFee;
        }
        withdrawFeePercent = withdrawFeePercent || 0;

        // Platform closing aliases for compatibility with frontend
        const autoOpenHour = (typeof settings.autoOpenHourUK === 'number') ? settings.autoOpenHourUK : 10;
        const hh = String(autoOpenHour).padStart(2, '0');
        const autoOpenTime = `${hh}:00`;

        const allowList = Array.isArray(settings.whoCanAccessDuringClose) ? settings.whoCanAccessDuringClose : [];

        res.json({
            service: settings && settings.service ? settings.service : { whatsapp: "", telegram: "" },
            platformClosed: !!settings.platformClosed,
            autoOpenHourUK: autoOpenHour,
            autoOpenTime,
            whoCanAccessDuringClose: allowList,
            allowList,
            withdrawFeePercent
        });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// Registration
router.post('/users/register', async (req, res) => {
    const {
        username,
        phone,
        loginPassword,
        withdrawalPassword,
        gender,
        inviteCode
    } = req.body;

    if (!username || !loginPassword || !withdrawalPassword || !phone || !inviteCode) {
        return res.status(400).json({ success: false, message: "All fields (username, phone, loginPassword, withdrawalPassword, inviteCode) are required." });
    }

    const usernameExists = await User.findOne({ username });
    if (usernameExists) {
        return res.json({ success: false, message: "Username already exists." });
    }

    const phoneExists = await User.findOne({ phone });
    if (phoneExists) {
        return res.json({ success: false, message: "Phone already registered." });
    }

    const referrer = await User.findOne({ $or: [{ inviteCode: inviteCode.trim() }, { invite_code: inviteCode.trim() }] });
    if (!referrer) {
        return res.json({ success: false, message: "Invalid invitation code. Please provide a valid code from an existing user." });
    }

    let userInviteCode, unique = false, tries = 0;
    while (!unique && tries < 1000) {
        userInviteCode = generateInviteCode();
        const exists = await User.findOne({ $or: [{ inviteCode: userInviteCode }, { invite_code: userInviteCode }] });
        if (!exists) unique = true;
        tries++;
    }
    if (!unique) {
        return res.status(500).json({ success: false, message: "Failed to generate unique invitation code." });
    }

    const newUser = {
        username: username.trim(),
        phone: phone.trim(),
        loginPassword: loginPassword.trim(),
        withdrawPassword: withdrawalPassword.trim(),
        gender: gender || "Male",
        inviteCode: userInviteCode,
        referredBy: inviteCode.trim(),
        vipLevel: 1,
        balance: 0,
        commission: 0,
        commissionToday: 0,
        lastCommissionReset: "", // <-- Added here for new users
        taskCountToday: 0,
        suspended: false,
        token: crypto.randomBytes(24).toString('hex'),
        createdAt: new Date().toISOString(),
        currentSet: 1
    };

    // Ensure _id is provided because the schema declares _id: String (Mongoose won't auto-generate a string _id)
    try {
      newUser._id = newUser._id || crypto.randomBytes(12).toString('hex');
      const created = await User.create(newUser);

      // --- New: record register event (IP + geo) and notify admin sockets ---
      try {
        const ip = getClientIp(req) || (req.ip || req.connection?.remoteAddress || '');
        const geo = geoLookup(ip);
        const userAgent = req.headers['user-agent'] || '';

        const evt = await LoginEvent.create({
          userId: created._id,
          ip,
          country: geo && geo.country,
          region: geo && geo.region,
          city: geo && geo.city,
          latitude: geo && geo.latitude,
          longitude: geo && geo.longitude,
          userAgent,
          action: 'register',
          createdAt: new Date().toISOString()
        });

        // Emit to admin room if Socket.IO is enabled on app
        try {
          const io = req.app && req.app.get && req.app.get('io');
          if (io) {
            io.to('admins').emit('user-event', {
              id: evt._id,
              userId: created._id,
              username: created.username || null,
              ip,
              country: geo && geo.country,
              region: geo && geo.region,
              city: geo && geo.city,
              userAgent,
              action: 'register',
              createdAt: evt.createdAt || evt.createdAt
            });
          }
        } catch (emitErr) {
          console.warn('Emit admin user-event (register) failed:', emitErr && emitErr.message ? emitErr.message : emitErr);
        }
      } catch (logErr) {
        console.warn('Failed to create register LoginEvent:', logErr && logErr.message ? logErr.message : logErr);
      }

      return res.json({ success: true, user: created });
    } catch (err) {
      console.error('users/register create error:', err && err.stack ? err.stack : err);
      // If we somehow hit an _id-related error, try a fallback id-generation (string)
      const msg = err && err.message ? err.message : String(err);
      if (msg.toLowerCase().includes('document must have an _id')) {
        try {
          newUser._id = crypto.randomBytes(16).toString('hex');
          const created2 = await User.create(newUser);

          // --- New: also log/register event for fallback-created user ---
          try {
            const ip2 = getClientIp(req) || (req.ip || req.connection?.remoteAddress || '');
            const geo2 = geoLookup(ip2);
            const userAgent2 = req.headers['user-agent'] || '';

            const evt2 = await LoginEvent.create({
              userId: created2._id,
              ip: ip2,
              country: geo2 && geo2.country,
              region: geo2 && geo2.region,
              city: geo2 && geo2.city,
              latitude: geo2 && geo2.latitude,
              longitude: geo2 && geo2.longitude,
              userAgent: userAgent2,
              action: 'register',
              createdAt: new Date().toISOString()
            });

            try {
              const io = req.app && req.app.get && req.app.get('io');
              if (io) {
                io.to('admins').emit('user-event', {
                  id: evt2._id,
                  userId: created2._id,
                  username: created2.username || null,
                  ip: ip2,
                  country: geo2 && geo2.country,
                  region: geo2 && geo2.region,
                  city: geo2 && geo2.city,
                  userAgent: userAgent2,
                  action: 'register',
                  createdAt: evt2.createdAt || evt2.createdAt
                });
              }
            } catch (emitErr2) {
              console.warn('Emit admin user-event (register fallback) failed:', emitErr2 && emitErr2.message ? emitErr2.message : emitErr2);
            }
          } catch (logErr2) {
            console.warn('Failed to create register LoginEvent for fallback user:', logErr2 && logErr2.message ? logErr2.message : logErr2);
          }

          return res.json({ success: true, user: created2 });
        } catch (err2) {
          console.error('users/register retry failed:', err2 && err2.stack ? err2.stack : err2);
          return res.status(500).json({ success: false, message: 'Failed to create user', error: err2 && err2.message ? err2.message : String(err2) });
        }
      }
      return res.status(500).json({ success: false, message: 'Internal server error', error: msg });
    }
});

// Authentication (login) — now creates a session record instead of overwriting a single user.token
router.post('/login', async (req, res) => {
    const input = req.body.input || req.body.username || "";
    const password = req.body.password;
    const user = await User.findOne({
        $or: [{ username: input }, { phone: input }],
        loginPassword: password
    });
    if (!user) {
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    if (user.suspended) return res.status(403).json({ success: false, message: 'Account suspended' });

    // generate per-login session token (opaque)
    const sessionToken = crypto.randomBytes(24).toString('hex');

    const sessionDoc = {
      token: sessionToken,
      userId: user._id,
      userAgent: req.headers['user-agent'] || '',
      ip: req.ip || req.connection?.remoteAddress || '',
      createdAt: new Date().toISOString(),
      lastUsedAt: null,
      // optional: set expiry (e.g. 30 days)
      // expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString()
    };

    try {
      await Session.create(sessionDoc);

      // --- New: record login event (IP + geo) and emit to admins ---
      try {
        const ip = getClientIp(req) || sessionDoc.ip || '';
        const geo = geoLookup(ip);
        const userAgent = req.headers['user-agent'] || '';

        const evt = await LoginEvent.create({
          userId: user._id,
          ip,
          country: geo && geo.country,
          region: geo && geo.region,
          city: geo && geo.city,
          latitude: geo && geo.latitude,
          longitude: geo && geo.longitude,
          userAgent,
          action: 'login',
          createdAt: new Date().toISOString()
        });

        try {
          const io = req.app && req.app.get && req.app.get('io');
          if (io) {
            io.to('admins').emit('user-event', {
              id: evt._id,
              userId: user._id,
              username: user.username || null,
              ip,
              country: geo && geo.country,
              region: geo && geo.region,
              city: geo && geo.city,
              userAgent,
              action: 'login',
              createdAt: evt.createdAt || evt.createdAt
            });
          }
        } catch (emitErr) {
          console.warn('Emit admin user-event (login) failed:', emitErr && emitErr.message ? emitErr.message : emitErr);
        }
      } catch (logErr) {
        console.warn('Failed to create login LoginEvent:', logErr && logErr.message ? logErr.message : logErr);
      }
    } catch (err) {
      console.error('Failed to create session:', err && err.message ? err.message : err);
      return res.status(500).json({ success: false, message: 'Failed to create session' });
    }

    // pre-warm product cache (non-blocking)
    fetchProductsFromCloudinary().catch(err => {
      console.warn('Cloudinary pre-warm after login failed:', err && err.message ? err.message : err);
    });

    // Return user and token. Do not overwrite other sessions.
    const userToReturn = user.toObject ? user.toObject() : user;
    userToReturn.token = sessionToken; // include session token in response (not persisted on user)
    return res.json({ success: true, user: userToReturn, token: sessionToken });
});

// Logout: revoke current session
router.post('/logout', verifyUserToken, async (req, res) => {
  try {
    // if we validated via Session, req.session will be present and persisted
    if (req.session && req.session._id) {
      await Session.updateOne({ _id: req.session._id }, { $set: { revoked: true } });
      return res.json({ success: true, message: 'Logged out' });
    }

    // Fallback: if legacy user.token was used, clear it (best-effort)
    if (req.user && req.user.token) {
      try {
        await User.updateOne({ _id: req.user._id }, { $set: { token: "" } });
      } catch (e) { /* ignore */ }
      return res.json({ success: true, message: 'Logged out (legacy)' });
    }

    return res.json({ success: true });
  } catch (err) {
    console.error('logout error:', err);
    return res.status(500).json({ success: false, message: 'Logout failed' });
  }
});

// Wallet bind
router.post('/bind-wallet', verifyUserToken, async (req, res) => {
    const { fullName, exchange, walletAddress } = req.body;
    const user = req.user;
    if (!exchange || !walletAddress) {
        return res.json({ success: false, message: "Exchange and wallet address required" });
    }
    if (fullName) user.fullName = fullName;
    user.exchange = exchange;
    user.walletAddress = walletAddress;
    await user.save();
    res.json({ success: true });
});

// User profile
router.get('/user-profile', verifyUserToken, async (req, res) => {
    const dbUser = await User.findOne({ username: req.user.username });
    if (!dbUser) return res.status(404).json({ success: false, message: "User not found" });

    if (typeof dbUser.currentSet !== "number") dbUser.currentSet = 1;

    // --- Midnight commission reset safety (use UK day) ---
    const todayStr = getUKDateKey();
    if (dbUser.lastCommissionReset !== todayStr) {
        dbUser.commissionToday = 0;
        dbUser.lastCommissionReset = todayStr;
        await dbUser.save();
    }

    const tasks = await Task.find({});
    const userSet = dbUser.currentSet || 1;
    const vipInfo = vipRules[dbUser.vipLevel] || vipRules[1];
    const taskCountThisSet = tasks.filter(
        t => t.username === dbUser.username && t.status?.toLowerCase() === "completed" && (t.set || 1) === userSet
    ).length;

    // Get registered sets count for today from stored map
    const regMap = dbUser.registeredWorkingDays || {};
    const registeredSetsToday = regMap[todayStr] || 0;

    res.json({
        success: true,
        user: {
            username: dbUser.username,
            balance: dbUser.balance ?? 0,
            vipLevel: dbUser.vipLevel ?? 1,
            commissionToday: dbUser.commissionToday ?? 0,
            taskCountThisSet,
            currentSet: dbUser.currentSet ?? 1,
            maxTasks: vipInfo.tasks,
            inviteCode: dbUser.inviteCode ?? "",
            referredBy: dbUser.referredBy ?? "",
            exchange: dbUser.exchange ?? "",
            walletAddress: dbUser.walletAddress ?? "",
            fullName: dbUser.fullName ?? "",
            // server-side working-day data
            registeredWorkingDays: regMap,
            registeredSetsToday,
            signState: dbUser.signState || { signedCount: 0, lastSignDate: null },
            resetRequested: !!dbUser.resetRequested
        }
    });
});

// Sign-in endpoint: persist sign state server-side for cross-device sync
router.post('/sign-in', verifyUserToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const REQUIRED_SETS = 2;
    const todayKey = getUKDateKey();
    const regMap = user.registeredWorkingDays || {};
    const setsToday = regMap[todayKey] || 0;

    if (setsToday < REQUIRED_SETS) {
      return res.status(400).json({ success: false, message: `You need to complete at least ${REQUIRED_SETS} sets today to sign in. Progress: ${setsToday}/${REQUIRED_SETS}` });
    }

    const yesterdayKey = getUKDateKey(new Date(Date.now() - 86400000));
    let newCount = 1;
    if (user.signState && user.signState.lastSignDate === yesterdayKey) {
      newCount = (user.signState.signedCount || 0) + 1;
    } else if (user.signState && user.signState.lastSignDate === todayKey) {
      newCount = user.signState.signedCount || 1;
    } else {
      newCount = 1;
    }
    if (newCount > 30) newCount = 30;

    const newSignState = { signedCount: newCount, lastSignDate: todayKey };
    user.signState = newSignState;
    await user.save();

    return res.json({ success: true, signState: newSignState });
  } catch (err) {
    console.error('sign-in error:', err);
    return res.status(500).json({ success: false, message: 'Sign-in failed', error: err.message });
  }
});

// Product recommendation
router.get('/recommend-product', verifyUserToken, async (req, res) => {
    const user = req.user;
    try {
        const products = await getCachedCloudinaryProducts();

        let affordable = products.filter(prod => prod.price <= user.balance);
        if (!affordable.length) affordable = products;
        if (!affordable.length) {
            return res.json({ success: false, message: "No products available for your balance." });
        }
        const chosenProduct = affordable[Math.floor(Math.random() * affordable.length)];

        const vipInfo = vipRules[user.vipLevel] || vipRules[1];
        const commission = Math.floor(chosenProduct.price * vipInfo.commissionRate * 100) / 100;

        res.json({
            success: true,
            product: {
                ...chosenProduct,
                commission
            }
        });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to fetch products', error: err.message });
    }
});

// Task records
router.get('/task-records', verifyUserToken, async (req, res) => {
    const tasks = await Task.find({ username: req.user.username });
    const user = req.user;
    let records = [];
    tasks.forEach(t => {
        if (t.isCombo && Array.isArray(t.products)) {
            if (t.status === 'Pending' || t.status === 'pending') {
                if (t.products.length === 2) {
                    records.push({
                        ...t.toObject(),
                        comboIndex: 0,
                        canSubmit: false,
                        status: 'Pending',
                        product: t.products[0]
                    });
                    records.push({
                        ...t.toObject(),
                        comboIndex: 1,
                        canSubmit: true,
                        status: 'Pending',
                        product: t.products[1]
                    });
                } else {
                    t.products.forEach((prod, idx) => {
                        records.push({
                            ...t.toObject(),
                            comboIndex: idx,
                            canSubmit: idx === t.products.length - 1,
                            status: 'Pending',
                            product: prod
                        });
                    });
                }
            } else {
                t.products.forEach((prod, idx) => {
                    records.push({
                        ...t.toObject(),
                        comboIndex: idx,
                        canSubmit: false,
                        status: 'Completed',
                        product: prod
                    });
                });
            }
        } else {
            records.push({
                ...t.toObject(),
                canSubmit: true
            });
        }
    });
    records.sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt));
    res.json({ success: true, records });
});

// Start task (with 30% starting-capital enforcement)
// Middleware checkPlatformStatus applied here to block when platformClosed.
router.post('/start-task', verifyUserToken, checkPlatformStatus, async (req, res) => {
    try {
        // Re-fetch fresh user doc to get up-to-date balance and setStartingBalance
        let user = await User.findById(req.user._id);
        if (!user) return res.status(401).json({ success: false, message: 'Unauthorized' });
        if (typeof user.toObject === 'function') user = user.toObject();

        if (typeof user.currentSet !== "number") user.currentSet = 1;
        const userSet = user.currentSet || 1;

        // === Robust task counting: fetch tasks only for the current set (treat legacy docs without set as set 1) ===
        let taskQuery;
        if (userSet === 1) {
          // include tasks with set === 1 OR missing set (legacy)
          taskQuery = { username: user.username, $or: [{ set: 1 }, { set: { $exists: false } }] };
        } else {
          taskQuery = { username: user.username, set: userSet };
        }
        const tasks = await Task.find(taskQuery).lean();

        // fetch combos for the user (unchanged)
        const combos = await Combo.find({ username: user.username }).lean();

        // counts
        const tasksStarted = tasks.length;
        const tasksCompleted = tasks.filter(t => (t.status || '').toLowerCase() === 'completed').length;

        // DEBUG: helpful log to diagnose off-by-one issues (remove or reduce level in prod)
        console.log('start-task debug', {
          username: user.username,
          userSet,
          tasksStarted,
          tasksCompleted,
          tasksPreview: tasks.map(t => ({ _id: t._id, set: t.set, status: t.status, startedAt: t.startedAt || t.createdAt })),
          comboTriggers: combos.map(c => ({ _id: c._id, trigger: c.triggerTaskNumber }))
        });

        // use the filtered tasks (same set) for pending-checks
        if (hasPendingComboTask(tasks || [], user)) {
            return res.json({ success: false, message: "You must submit all combo products before starting new tasks." });
        }
        if (hasPendingTask(tasks || [], user)) {
            return res.json({ success: false, message: "You must submit your current product before starting another." });
        }

        if (tasksStarted === 0 && user.balance < 50) {
            return res.json({ success: false, message: 'You need at least £50 balance to start your first task set.' });
        }
        const vipInfo = vipRules[user.vipLevel] || vipRules[1];
        const maxTasks = vipInfo.tasks;
        if (tasksStarted >= maxTasks) {
            return res.json({ success: false, message: 'You have completed your current set. Please ask admin to reset your account for the next set.' });
        }

        // Determine setStartingBalance: record current balance when first task in a set is started
        let setStartingBalance = user.setStartingBalance;
        if (tasksStarted === 0) {
          setStartingBalance = Number(user.balance || 0);
          await User.updateOne({ _id: user._id }, { $set: { setStartingBalance } });
        }
        setStartingBalance = Number(setStartingBalance || user.balance || 0);

        // compute minimum allowed price (30% of setStartingBalance)
        const minAllowedPrice = Math.round((setStartingBalance * MIN_STARTING_CAPITAL_PERCENT + Number.EPSILON) * 100) / 100;

        // fetch products (fast cached getter)
        const products = await getCachedCloudinaryProducts();

        // Filter products: enforce both affordability and minAllowedPrice
        let affordable = (products || []).filter(p => p && typeof p.price === 'number' && p.price <= user.balance && p.price >= minAllowedPrice);

        // If none found within user's current balance, relax to all cached products but still enforce minAllowedPrice
        if (!affordable.length) {
          affordable = (products || []).filter(p => p && typeof p.price === 'number' && p.price >= minAllowedPrice);
        }

        if (!affordable.length) {
            return res.status(400).json({ success: false, message: `No products available matching the starting-capital rule. Minimum product price must be at least ${minAllowedPrice.toFixed(2)} GBP (30% of your set starting capital).` });
        }

        const chosenProduct = affordable[Math.floor(Math.random() * affordable.length)];

        // Combo logic (for combos enforce that comboTotal >= minAllowedPrice)
        let comboToTrigger = null;

        /*
          Semantics decision:
          - The code originally triggered when Number(combo.triggerTaskNumber) === (tasksStarted + 1)
            (i.e. when the user is starting the Nth task).
          - To avoid off-by-one issues caused by tasks from other sets or missing set fields,
            we now count tasks strictly for the current set (above). We now match combos by
            the number of completed tasks (tasksCompleted), so a combo with trigger=14 will be
            considered after the user has 14 completed tasks (and the next start will create the combo task).
        */

        comboToTrigger = combos.find(combo =>
            Number(combo.triggerTaskNumber) === tasksCompleted && combo.username === user.username
        );

        if (comboToTrigger && comboToTrigger.products && comboToTrigger.products.length === 2) {
            const comboTotal = comboToTrigger.products.reduce((sum, prod) => sum + Number(prod.price || 0), 0);

            if (comboTotal < minAllowedPrice) {
              return res.status(400).json({ success: false, message: `Combo total (${comboTotal.toFixed(2)} GBP) does not meet the minimum starting-capital rule (${minAllowedPrice.toFixed(2)} GBP).` });
            }

            await User.updateOne(
                { _id: user._id },
                { $inc: { balance: -comboTotal } }
            );

            const taskCode = crypto.randomBytes(10).toString('hex');
            const now = new Date().toISOString();

            const comboTask = {
                username: user.username,
                products: comboToTrigger.products.map(prod => ({
                    ...prod,
                    image: prod.image && typeof prod.image === 'string' && prod.image.trim() !== '' && prod.image !== 'null'
                        ? prod.image
                        : chosenProduct.image,
                    status: 'Pending',
                    submitted: false,
                    createdAt: now,
                    code: crypto.randomBytes(6).toString('hex')
                })),
                status: 'Pending',
                startedAt: now,
                taskCode,
                set: userSet,
                isCombo: true
            };

            await Task.create(comboTask);

            const updatedUser = await User.findById(user._id);
            const isNegative = updatedUser.balance < 0;

            return res.json({
                success: true,
                task: comboTask,
                isCombo: true,
                comboMustSubmitAllAtOnce: true,
                currentBalance: updatedUser.balance,
                isNegativeBalance: isNegative
            });
        }

        // Single task flow
        if (user.balance < chosenProduct.price) {
            return res.json({ success: false, message: 'Insufficient balance for recommended product.' });
        }
        const commission = Math.floor(chosenProduct.price * vipInfo.commissionRate * 100) / 100;

        await User.updateOne(
            { _id: user._id },
            { $inc: { balance: -chosenProduct.price } }
        );

        const taskCode = crypto.randomBytes(10).toString('hex');

        const task = {
            username: user.username,
            product: {
                name: chosenProduct.name,
                price: chosenProduct.price,
                commission,
                image: chosenProduct.image,
                createdAt: new Date().toISOString(),
                code: crypto.randomBytes(6).toString('hex'),
                public_id: chosenProduct.public_id,
                description: chosenProduct.description
            },
            status: 'Pending',
            startedAt: new Date().toISOString(),
            taskCode,
            set: userSet
        };

        await Task.create(task);

        res.json({ success: true, task });
    } catch (err) {
        console.error('start-task error:', err);
        res.status(500).json({ success: false, message: 'Internal server error', error: err.message });
    }
});

// ----------------------- Optimized submit-task: target < 1.5s -----------------------
// Key optimizations:
// - Use lean() when reading the task
// - Perform User and Task updates in parallel (Promise.all)
// - Do not await distributeReferralCommission; fire-and-forget it so response returns fast
// - Build response object locally to avoid an extra DB read
// Middleware checkPlatformStatus applied here to block when platformClosed.
router.post('/submit-task', verifyUserToken, checkPlatformStatus, async (req, res) => {
    const { taskCode } = req.body;
    const user = req.user;

    try {
      // Read task in lean mode (fast)
      const task = await Task.findOne({ taskCode, username: user.username }).lean();
      if (!task) return res.status(404).json({ success: false, message: 'Task not found' });

      // Combo tasks
      if (task.isCombo && Array.isArray(task.products)) {
        if (user.balance < 0) {
          return res.json({ success: false, mustDeposit: true, message: "Insufficient balance. Please deposit to clear negative balance before submitting combo products." });
        }

        const now = new Date().toISOString();
        const updatedProducts = task.products.map(prod => ({ ...prod, status: 'Completed', submitted: true, completedAt: now }));

        const totalRefund = updatedProducts.reduce((sum, prod) => sum + Number(prod.price || 0), 0);
        const totalCommission = updatedProducts.reduce((sum, prod) => sum + Number(prod.commission || 0), 0);

        // Parallel updates: user balance and task status
        const userUpdatePromise = User.updateOne(
          { _id: user._id },
          { $inc: { balance: totalRefund + totalCommission, commission: totalCommission, commissionToday: totalCommission } }
        );
        const taskUpdatePromise = Task.updateOne(
          { _id: task._id },
          { $set: { products: updatedProducts, status: 'Completed', completedAt: now } }
        );

        await Promise.all([userUpdatePromise, taskUpdatePromise]);

        // Fire-and-forget referral distribution so we return quickly (<1.5s)
        (async () => {
          try {
            const sourceRef = `task:${task._id}:completed`;
            await distributeReferralCommission({
              sourceUserId: user._id,
              originalAmount: totalCommission,
              sourceReference: sourceRef,
              sourceType: 'task',
              note: `Referral from combo task ${task._id}`
            });
          } catch (err) {
            console.error('Referral distribution failed (combo, async):', err);
          }
        })();

        // After marking completed, check if the set is now complete
        try {
          const taskSet = task.set || 1;
          const vipInfo = vipRules[user.vipLevel] || vipRules[1];
          const completedCount = await Task.countDocuments({ username: user.username, set: taskSet, status: { $regex: /^completed$/i } });
          if (completedCount >= (vipInfo.tasks || 40)) {
            const todayKey = getUKDateKey();
            // Atomically increment registeredWorkingDays[todayKey], and mark that reset is requested.
            // IMPORTANT: do NOT auto-increment currentSet anymore.
            const updates = {
              $inc: { [`registeredWorkingDays.${todayKey}`]: 1 },
              $set: { setStartingBalance: null, resetRequested: true }
            };
            await User.updateOne({ _id: user._id }, updates);
            // do NOT increment currentSet automatically here
          }
        } catch (err) {
          console.error('post-combo-completion bookkeeping failed:', err);
        }

        // Construct response without doing another DB read
        const responseTask = {
          ...task,
          products: updatedProducts,
          status: 'Completed',
          completedAt: now
        };

        return res.json({ success: true, task: responseTask });
      }

      // Normal task flow
      if (task.status?.toLowerCase() !== 'pending') {
        return res.status(404).json({ success: false, message: 'Task already submitted or not pending' });
      }

      const vipInfo = vipRules[user.vipLevel] || vipRules[1];
      const price = Number(task.product.price);
      const commission = Math.floor(price * vipInfo.commissionRate * 100) / 100;
      const now = new Date().toISOString();

      // Parallel updates: user and task (fast)
      const userUpdatePromise = User.updateOne(
        { _id: user._id },
        { $inc: { balance: price + commission, commission: commission, commissionToday: commission } }
      );

      const taskUpdatePromise = Task.updateOne(
        { _id: task._id },
        { $set: { status: 'Completed', completedAt: now, 'product.commission': commission } }
      );

      await Promise.all([userUpdatePromise, taskUpdatePromise]);

      // Fire-and-forget referral distribution (async) so we don't block the response
      (async () => {
        try {
          const sourceRef = `task:${task._id}:completed`;
          await distributeReferralCommission({
            sourceUserId: user._id,
            originalAmount: commission,
            sourceReference: sourceRef,
            sourceType: 'task',
            note: `Referral from task ${task._id}`
          });
        } catch (err) {
          console.error('Referral distribution failed (single, async):', err);
        }
      })();

      // After marking this task completed, check whether the set is finished
      try {
        const taskSet = task.set || 1;
        const completedCount = await Task.countDocuments({ username: user.username, set: taskSet, status: { $regex: /^completed$/i } });
        if (completedCount >= (vipInfo.tasks || 40)) {
          const todayKey = getUKDateKey();
          // Atomically increment registeredWorkingDays[todayKey] and set resetRequested flag.
          // IMPORTANT: do NOT auto-increment currentSet anymore.
          const updates = {
            $inc: { [`registeredWorkingDays.${todayKey}`]: 1 },
            $set: { setStartingBalance: null, resetRequested: true }
          };
          await User.updateOne({ _id: user._id }, updates);
          // do not increment currentSet automatically here
        }
      } catch (err) {
        console.error('post-task-completion bookkeeping failed:', err);
      }

      // Build response locally to avoid extra DB read
      const responseTask = {
        ...task,
        status: 'Completed',
        completedAt: now,
        product: {
          ...task.product,
          commission
        }
      };

      return res.json({ success: true, task: responseTask });
    } catch (err) {
      console.error('submit-task error:', err);
      return res.status(500).json({ success: false, message: 'Internal server error', error: err.message });
    }
});

// ----------------------- Admin Endpoint: Reset User Task Set -----------------------
router.post('/admin/reset-user-task-set', async (req, res) => {
    const { username, adminSecret } = req.body;
    const ADMIN_SECRET = 'yoursecretpassword';
    if (adminSecret !== ADMIN_SECRET) {
        return res.status(403).json({ success: false, message: 'Unauthorized' });
    }
    const user = await User.findOne({ username });
    if (!user) {
        return res.json({ success: false, message: 'User not found.' });
    }
    if (typeof user.currentSet !== "number") user.currentSet = 1;
    user.currentSet += 1;
    // Clear setStartingBalance so next set will record a fresh starting capital
    // Also clear resetRequested flag because admin performed the reset
    await User.updateOne({ _id: user._id }, { $set: { currentSet: user.currentSet, setStartingBalance: null, resetRequested: false } });
    res.json({ success: true, message: 'User task set has been reset. They can start a new set now.' });
});

// ----------------------- Admin Endpoint: Set Platform Status (NEW) -----------------------
router.post('/admin/set-platform-status', async (req, res) => {
    const { closed, autoOpenHourUK, allowList, autoOpenTime, adminSecret } = req.body;
    const ADMIN_SECRET = 'yoursecretpassword';
    if (adminSecret !== ADMIN_SECRET) {
        return res.status(403).json({ success: false, message: 'Unauthorized' });
    }

    let settings = await getOrCreateSettings();

    const updates = {};
    if (typeof closed === 'boolean') updates.platformClosed = closed;

    // Accept autoOpenHourUK as number OR autoOpenTime ("HH:MM")
    if (autoOpenHourUK !== undefined && !isNaN(Number(autoOpenHourUK))) {
      updates.autoOpenHourUK = Number(autoOpenHourUK);
    } else if (typeof autoOpenTime === 'string' && autoOpenTime.trim()) {
      const parts = autoOpenTime.split(':');
      const parsed = parseInt(parts[0], 10);
      if (!isNaN(parsed) && parsed >= 0 && parsed <= 23) updates.autoOpenHourUK = parsed;
    }

    // allowList can be array or comma-separated string; store into whoCanAccessDuringClose
    if (Array.isArray(allowList)) {
      updates.whoCanAccessDuringClose = allowList;
    } else if (typeof allowList === 'string' && allowList.trim()) {
      updates.whoCanAccessDuringClose = allowList.split(',').map(s => s.trim()).filter(Boolean);
    }

    if (Object.keys(updates).length) {
      await Setting.updateOne({ _id: settings._id }, { $set: updates });
      settings = await Setting.findById(settings._id);
    }

    res.json({ success: true, settings: {
      platformClosed: !!settings.platformClosed,
      autoOpenHourUK: typeof settings.autoOpenHourUK === 'number' ? settings.autoOpenHourUK : 10,
      whoCanAccessDuringClose: Array.isArray(settings.whoCanAccessDuringClose) ? settings.whoCanAccessDuringClose : []
    }});
});

// ----------------------- User Endpoint: Request Reset for Next Set -----------------------
router.post('/users/request-reset', verifyUserToken, async (req, res) => {
  try {
    const user = req.user;
    if (!user) return res.status(401).json({ success: false, message: 'Unauthorized' });

    // Mark that the user has requested reset for next set.
    await User.updateOne({ _id: user._id }, { $set: { resetRequested: true } });
    return res.json({ success: true, message: 'Reset requested. An admin will process your reset, or use the admin endpoint to perform it.' });
  } catch (err) {
    console.error('request-reset error:', err);
    return res.status(500).json({ success: false, message: 'Failed to request reset', error: err.message });
  }
});

// Deposit
router.post('/deposit', verifyUserToken, async (req, res) => {
    const { amount } = req.body;
    const user = req.user;
    if (!amount || isNaN(amount) || Number(amount) <= 0) {
        return res.json({ success: false, message: "Invalid amount" });
    }
    user.balance = (user.balance || 0) + Number(amount);

    await Deposit.create({
        username: user.username,
        amount: Number(amount),
        createdAt: new Date().toISOString(),
        status: "Completed"
    });

    await user.save();

    res.json({ success: true });
});

// Withdraw
// Middleware checkPlatformStatus applied here to block when platformClosed.
router.post('/withdraw', verifyUserToken, checkPlatformStatus, async (req, res) => {
    const { amount, withdrawPassword } = req.body;
    const user = req.user;

    if (!amount || isNaN(amount) || Number(amount) <= 0) {
        return res.json({ success: false, message: "Invalid amount" });
    }
    if (!withdrawPassword) {
        return res.json({ success: false, message: "Withdrawal password required" });
    }
    let actualWithdrawPwd = user.withdrawPassword || user.withdrawalPassword;
    if (!actualWithdrawPwd || actualWithdrawPwd !== withdrawPassword) {
        return res.json({ success: false, message: "Incorrect withdrawal password." });
    }
    if (Number(amount) > (user.balance || 0)) {
        return res.json({ success: false, message: "Insufficient balance" });
    }
    user.balance -= Number(amount);

    await Withdrawal.create({
        id: crypto.randomBytes(12).toString('hex'),
        username: user.username,
        amount: Number(amount),
        createdAt: new Date().toISOString(),
        status: "Pending"
    });

    await user.save();

    res.json({ success: true });
});

// Transactions
router.get('/transactions', verifyUserToken, async (req, res) => {
    const user = req.user;
    const deposits = await Deposit.find({ username: user.username });

    let adminTransactions = [];
    try {
        const allTransactions = await Transaction.find({ $or: [{ user: user.username }, { username: user.username }] });
        adminTransactions = allTransactions.filter(
            tx =>
                (tx.type === "admin_add_balance" || tx.type === "admin_add_funds" || tx.type === "add_balance_admin")
        ).map(tx => ({
            username: tx.user || tx.username,
            amount: tx.amount,
            createdAt: tx.createdAt || tx.date || new Date().toISOString(),
            status: tx.status || "Completed",
            type: tx.type || "admin_add_balance",
            id: tx.id
        }));
    } catch (err) {
        adminTransactions = [];
    }

    const allDeposits = [
        ...deposits.map(d => ({ ...d.toObject(), type: "deposit" })),
        ...adminTransactions
    ].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    const withdrawals = await Withdrawal.find({ username: user.username });

    res.json({ success: true, deposits: allDeposits, withdrawals });
});

// Verify withdraw password
router.post('/verify-withdraw-password', verifyUserToken, async (req, res) => {
    const { password } = req.body;
    const user = req.user;

    let actualWithdrawPwd = user.withdrawPassword || user.withdrawalPassword;

    if (!actualWithdrawPwd) {
        return res.json({ success: false, message: "No withdrawal password is set." });
    }
    if (actualWithdrawPwd === password) {
        return res.json({ success: true });
    } else {
        return res.json({ success: false, message: "Incorrect withdrawal password." });
    }
});

// Change password
router.post('/change-password', verifyUserToken, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    // Re-fetch the latest user doc from DB
    const user = await User.findById(req.user._id);

    if (!user.loginPassword || user.loginPassword !== oldPassword) {
        return res.json({ success: false, message: "Old password is incorrect." });
    }

    user.loginPassword = newPassword;

    // Revoke all active sessions for this user so tokens must be reissued
    try {
      await Session.updateMany({ userId: user._id, revoked: { $ne: true } }, { $set: { revoked: true } });
    } catch (err) {
      console.warn('Failed to revoke sessions on password change:', err && err.message ? err.message : err);
    }

    // Optionally clear legacy token field for full compatibility (not required)
    try {
      user.token = "";
      await user.save();
    } catch (err) {
      console.error('Failed to save user after password change:', err);
      return res.status(500).json({ success: false, message: "Failed to update password, try again later." });
    }

    res.json({ success: true, message: "Password updated successfully. Please log in again." });
});

// Change withdraw password
router.post('/change-withdraw-password', verifyUserToken, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const user = req.user;

    let current = user.withdrawPassword || user.withdrawalPassword;
    if (!current || current !== oldPassword) {
        return res.json({ success: false, message: "Old withdrawal password is incorrect." });
    }
    user.withdrawPassword = newPassword;
    if (user.withdrawalPassword) user.withdrawalPassword = undefined;

    try {
        await user.save();
        res.json({ success: true, message: "Withdrawal password updated successfully." });
    } catch (err) {
        res.status(500).json({ success: false, message: "Failed to save new withdrawal password. Try again later." });
    }
});

// Notifications
router.get('/notifications', verifyUserToken, async (req, res) => {
    const notifications = await Notification.find({}).sort({ date: -1 });
    res.json({ success: true, notifications });
});

router.post('/admin/notification', async (req, res) => {
    const { title, message } = req.body;
    await Notification.create({
        id: Date.now(),
        title,
        message,
        date: new Date().toISOString()
    });
    res.json({ success: true });
});

module.exports = router;

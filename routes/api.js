const express = require('express');
const crypto = require('crypto');
const mongoose = require('mongoose');
const cloudinary = require('cloudinary').v2;
const axios = require('axios');
const fs = require('fs');
const path = require('path');

const { distributeReferralCommission } = require('./commissionService');

const router = express.Router();

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
  resetRequested: { type: Boolean, default: false },

  // Persisted frozen amount so frontend can show deducted amount across refreshes.
  frozenAmount: { type: Number, default: 0 }
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

// New: LoginAudit model for persistent audit of register/login events
const LoginAudit = mongoose.models.LoginAudit || mongoose.model('LoginAudit',
  new mongoose.Schema({
    userId: String,
    username: String,
    event: String, // 'login' | 'register' | other
    ip: String,
    geo: mongoose.Schema.Types.Mixed,
    userAgent: String,
    createdAt: { type: String, default: () => new Date().toISOString() }
  }, { collection: 'loginaudit', strict: false })
);

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

// ---------------- Admin notification helpers (Telegram / Slack) ----------------
// Place your TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in environment variables.
// Optional: SLACK_WEBHOOK_URL for Slack notifications.
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "";
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || "";
const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL || "";

// Normalize IP helpers (handles ::ffff: IPv4 mapped addresses)
function normalizeIp(ip) {
  if (!ip) return "";
  const s = String(ip).trim();
  // match IPv4 inside IPv6 mapped (::ffff:1.2.3.4)
  const m = s.match(/(?:.*:)?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$/);
  return m ? m[1] : s;
}

// Robust extraction of client IP from request (x-forwarded-for, x-real-ip, req.ip, connection, socket)
function getClientIp(req) {
  try {
    const xf = req.headers['x-forwarded-for'] || req.headers['X-Forwarded-For'];
    if (xf && typeof xf === 'string') {
      const parts = xf.split(',').map(s => s.trim()).filter(Boolean);
      if (parts.length) return normalizeIp(parts[0]);
    }
    const xr = req.headers['x-real-ip'] || req.headers['X-Real-Ip'];
    if (xr) return normalizeIp(xr);
    if (req.ip) return normalizeIp(req.ip);
    if (req.connection && req.connection.remoteAddress) return normalizeIp(req.connection.remoteAddress);
    if (req.socket && req.socket.remoteAddress) return normalizeIp(req.socket.remoteAddress);
    return "";
  } catch (e) {
    return "";
  }
}

// Best-effort geo lookup using ip-api.com (free service, rate-limited). Returns object or null.
async function getGeoForIp(ip) {
  if (!ip) return null;
  try {
    const url = `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,regionName,city,zip,lat,lon,isp,org,query,message`;
    const r = await axios.get(url, { timeout: 2500 });
    if (r && r.data && r.data.status === "success") {
      return r.data;
    }
    return null;
  } catch (e) {
    return null;
  }
}

// Fire-and-forget admin notification (Telegram + optional Slack). Minimal info only.
// Modified: accept extra.geo and extra.userAgent to avoid recomputing different values.
async function notifyAdmin({ event = "unknown", user = {}, req = null, extra = {} } = {}) {
  try {
    const ip = extra.ip || (req ? getClientIp(req) : (extra.ip || "unknown"));
    const geo = extra.geo || (await getGeoForIp(ip));
    const time = new Date().toISOString();

    // Build readable location snippet
    let locationText = "";
    if (geo) {
      locationText = `${geo.city || ""}${geo.regionName ? ", " + geo.regionName : ""}${geo.country ? ", " + geo.country : ""}`.replace(/^, /, "");
      if (geo.isp) locationText += ` — ${geo.isp}`;
    } else if (extra.location) {
      locationText = String(extra.location);
    } else {
      locationText = "Location not available";
    }

    // Minimal user info (avoid sensitive fields)
    const usernameLine = `username: ${user.username || user.user || user.name || ""}`;
    const userIdLine = `userId: ${user._id || user.id || ""}`;

    const ua = extra.userAgent || (req ? (req.headers['user-agent'] || '') : '');
    let mapsLink = "";
    if (geo && geo.lat && geo.lon) {
      mapsLink = `\nMap: https://www.google.com/maps/search/?api=1&query=${geo.lat},${geo.lon}`;
    }

    const eventLine = `<b>${event.toUpperCase()}</b>`;
    const message = `${eventLine}\n${usernameLine}\n${userIdLine}\nIP: <code>${ip}</code>\nLocation: ${locationText}${mapsLink}\nUser-Agent: ${ua}\nTime: ${time}`;

    // Telegram
    if (TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID) {
      try {
        const tgUrl = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
        await axios.post(tgUrl, {
          chat_id: TELEGRAM_CHAT_ID,
          text: message,
          parse_mode: "HTML",
        }, { timeout: 3000 });
      } catch (e) {
        console.warn('notifyAdmin: telegram send failed', e && e.message ? e.message : e);
      }
    }

    // Slack (optional)
    if (SLACK_WEBHOOK_URL) {
      try {
        const slackText = `${event.toUpperCase()} — ${user.username || user._id || ""}\nIP: ${ip}\nLocation: ${locationText}\nTime: ${time}`;
        await axios.post(SLACK_WEBHOOK_URL, { text: slackText }, { timeout: 3000 });
      } catch (e) {
        console.warn('notifyAdmin: slack send failed', e && e.message ? e.message : e);
      }
    }

    console.log(`notifyAdmin: ${event} ${user.username || user._id || ''} ip=${ip} loc=${locationText}`);
  } catch (err) {
    console.error('notifyAdmin error:', err && err.message ? err.message : err);
  }
}
// ---------------- end notification helpers ----------------

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
        const hh = String(autoOpenHour).padStart(2, "0");
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

// -------- NEW PUBLIC SERVICE-LINKS ROUTE --------
// Returns the serviceLinks map stored in Settings.serviceLinks (if present).
// Fallback: read public/service-links.json file if DB document does not have serviceLinks.
// Sets CORS headers to allow requests from the frontend origin.
router.get('/service-links', async (req, res) => {
  (async () => {
    try {
      const FRONTEND_ORIGIN = 'https://keymusecommerce.com';
      // Attempt to read from DB
      let settingsDoc = null;
      try {
        settingsDoc = await Setting.findOne({}).lean();
      } catch (e) {
        settingsDoc = null;
      }

      if (settingsDoc && settingsDoc.serviceLinks && typeof settingsDoc.serviceLinks === 'object') {
        res.setHeader('Access-Control-Allow-Origin', FRONTEND_ORIGIN);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        return res.json({ success: true, source: 'db', data: settingsDoc.serviceLinks });
      }

      // Fallback to public file (public/service-links.json)
      try {
        const filePath = path.join(__dirname, '..', 'public', 'service-links.json');
        const raw = fs.readFileSync(filePath, 'utf8');
        const parsed = JSON.parse(raw);
        res.setHeader('Access-Control-Allow-Origin', FRONTEND_ORIGIN);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        return res.json({ success: true, source: 'file', data: parsed });
      } catch (fileErr) {
        res.setHeader('Access-Control-Allow-Origin', FRONTEND_ORIGIN);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        return res.status(404).json({ success: false, message: 'No service links found' });
      }
    } catch (err) {
      console.error('GET /service-links error:', err && err.message ? err.message : err);
      res.setHeader('Access-Control-Allow-Origin', 'https://keymusecommerce.com');
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      return res.status(500).json({ success: false, message: 'Failed to read service links' });
    }
  })();
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
        currentSet: 1,
        frozenAmount: 0
    };

    // Ensure _id is provided because the schema declares _id: String (Mongoose won't auto-generate a string _id)
    try {
      newUser._id = newUser._id || crypto.randomBytes(12).toString('hex');
      const created = await User.create(newUser);

      // Determine canonical ip/userAgent/geo for this request and use the same for notify and audit
      const ipAddr = getClientIp(req) || '';
      const ua = req.headers['user-agent'] || '';
      const geo = await getGeoForIp(ipAddr);

      // Notify admin (fire-and-forget) about new registration
      (async () => {
        try {
          await notifyAdmin({
            event: "user_registered",
            user: { username: created.username, _id: created._id },
            req,
            extra: { ip: ipAddr, userAgent: ua, geo, location: geo ? `${geo.city || ''}${geo.regionName ? ', ' + geo.regionName : ''}${geo.country ? ', ' + geo.country : ''}` : '' }
          });
        } catch (e) { /* ignore notify errors */ }
      })();

      // Persist audit record (fire-and-forget)
      (async () => {
        try {
          await LoginAudit.create({
            userId: created._id,
            username: created.username,
            event: 'register',
            ip: ipAddr,
            geo,
            userAgent: ua,
            createdAt: new Date().toISOString()
          });
        } catch (e) {
          console.warn('LoginAudit create failed (register):', e && e.message ? e.message : e);
        }
      })();

      return res.json({ success: true, user: created });
    } catch (err) {
      console.error('users/register create error:', err && err.stack ? err.stack : err);
      // If we somehow hit an _id-related error, try a fallback id-generation (string)
      const msg = err && err.message ? err.message : String(err);
      if (msg.toLowerCase().includes('document must have an _id')) {
        try {
          newUser._id = crypto.randomBytes(16).toString('hex');
          const created2 = await User.create(newUser);

          // Determine canonical ip/userAgent/geo for this request (retry branch)
          const ipAddr = getClientIp(req) || '';
          const ua = req.headers['user-agent'] || '';
          const geo = await getGeoForIp(ipAddr);

          // Notify admin (fire-and-forget) about new registration (retry branch)
          (async () => {
            try {
              await notifyAdmin({
                event: "user_registered",
                user: { username: created2.username, _id: created2._id },
                req,
                extra: { ip: ipAddr, userAgent: ua, geo, location: geo ? `${geo.city || ''}${geo.regionName ? ', ' + geo.regionName : ''}${geo.country ? ', ' + geo.country : ''}` : '' }
              });
            } catch (e) { /* ignore notify errors */ }
          })();

          // Persist audit record for retry branch
          (async () => {
            try {
              await LoginAudit.create({
                userId: created2._id,
                username: created2.username,
                event: 'register',
                ip: ipAddr,
                geo,
                userAgent: ua,
                createdAt: new Date().toISOString()
              });
            } catch (e) {
              console.warn('LoginAudit create failed (register retry):', e && e.message ? e.message : e);
            }
          })();

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

    // Determine canonical ip/userAgent early so sessionDoc and subsequent messages share it
    const ipFromReq = getClientIp(req) || '';
    const uaHeader = req.headers['user-agent'] || '';

    // generate per-login session token (opaque)
    const sessionToken = crypto.randomBytes(24).toString('hex');

    const sessionDoc = {
      token: sessionToken,
      userId: user._id,
      userAgent: uaHeader,
      ip: ipFromReq,
      createdAt: new Date().toISOString(),
      lastUsedAt: null,
      // optional: set expiry (e.g. 30 days)
      // expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString()
    };

    try {
      await Session.create(sessionDoc);
    } catch (err) {
      console.error('Failed to create session:', err && err.message ? err.message : err);
      return res.status(500).json({ success: false, message: 'Failed to create session' });
    }

    // Resolve geo now and reuse both for notify and audit (avoid inconsistent lookups)
    const geoForIp = await getGeoForIp(ipFromReq);

    // Notify admin about login (fire-and-forget) - use canonical ip/ua/geo
    (async () => {
      try {
        await notifyAdmin({
          event: "user_logged_in",
          user: { username: user.username, _id: user._id },
          req,
          extra: { ip: ipFromReq, userAgent: uaHeader, geo: geoForIp, location: geoForIp ? `${geoForIp.city || ''}${geoForIp.regionName ? ', ' + geoForIp.regionName : ''}${geoForIp.country ? ', ' + geoForIp.country : ''}` : '' }
        });
      } catch (e) { /* ignore notify errors */ }
    })();

    // Persist audit record for login (fire-and-forget) using same canonical data
    (async () => {
      try {
        await LoginAudit.create({
          userId: user._id,
          username: user.username,
          event: 'login',
          ip: ipFromReq,
          geo: geoForIp,
          userAgent: uaHeader,
          createdAt: new Date().toISOString()
        });
      } catch (e) {
        console.warn('LoginAudit create failed (login):', e && e.message ? e.message : e);
      }
    })();

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
            resetRequested: !!dbUser.resetRequested,
            frozenAmount: Number(dbUser.frozenAmount || 0)
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

// ... remaining endpoints unchanged ...
// (The remainder of the file is unchanged from previous implementation and omitted here for brevity in the message; 
//  ensure the rest of your original api file content follows here exactly, including submit-task, start-task, admin endpoints, etc.)

module.exports = router;

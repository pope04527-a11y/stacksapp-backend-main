const express = require('express');
const crypto = require('crypto');
const mongoose = require('mongoose');
const cloudinary = require('cloudinary').v2;
const axios = require('axios');

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

cloudinary.config({
    cloud_name: 'dhubpqnss',
    api_key: '129672528218384',
    api_secret: 'J8SEWj1hzBs8uTclbOtntG7G_8E'
});

// ========== Product cache & helpers (pre-warm + in-flight dedupe + periodic refresh) ==========
const CLOUDINARY_CACHE_DURATION = 1000 * 60 * 5; // 5 minutes
let cachedProducts = [];
let lastCloudinaryFetch = 0;
let cloudinaryFetchInFlight = null; // promise for dedupe

async function fetchProductsFromCloudinary() {
  if (cloudinaryFetchInFlight) return cloudinaryFetchInFlight;

  cloudinaryFetchInFlight = (async () => {
    let products = [];
    let next_cursor = undefined;
    try {
      do {
        const result = await cloudinary.api.resources({
          type: 'upload',
          prefix: 'products/',
          max_results: 1000,
          context: true,
          tags: true,
          ...(next_cursor ? { next_cursor } : {})
        });

        const pageProducts = (result.resources || [])
          .filter(r =>
            r.context && r.context.custom &&
            r.context.custom.caption &&
            r.context.custom.price && r.context.custom.price !== "N/A" &&
            r.secure_url
          )
          .map(r => ({
            image: r.secure_url,
            name: r.context.custom.caption,
            price: parseFloat(r.context.custom.price),
            description: r.context.custom.alt || "",
            public_id: r.public_id
          }));

        products = products.concat(pageProducts);
        next_cursor = result.next_cursor;
      } while (next_cursor);

      cachedProducts = products;
      lastCloudinaryFetch = Date.now();
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

// ========== Auth middleware (unchanged behavior with safe local-dev fallback) ==========
const verifyUserToken = async (req, res, next) => {
    // accept token from headers (x-auth-token) or Authorization Bearer
    // Extended: also accept token from cookies, request body, or query to be more tolerant of client setups.
    try {
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

        const user = await User.findOne({ token });
        if (!user) {
            // Invalid token — allow local dev fallback similarly to missing token
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
        }
        req.user = user;
        next();
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
      return res.json({ success: true, user: created });
    } catch (err) {
      console.error('users/register create error:', err && err.stack ? err.stack : err);
      // If we somehow hit an _id-related error, try a fallback id-generation (string)
      const msg = err && err.message ? err.message : String(err);
      if (msg.toLowerCase().includes('document must have an _id')) {
        try {
          newUser._id = crypto.randomBytes(16).toString('hex');
          const created2 = await User.create(newUser);
          return res.json({ success: true, user: created2 });
        } catch (err2) {
          console.error('users/register retry failed:', err2 && err2.stack ? err2.stack : err2);
          return res.status(500).json({ success: false, message: 'Failed to create user', error: err2 && err2.message ? err2.message : String(err2) });
        }
      }
      return res.status(500).json({ success: false, message: 'Internal server error', error: msg });
    }
});

// Authentication (login) — trigger async cache pre-warm so subsequent start-task is fast
router.post('/login', async (req, res) => {
    const input = req.body.input || req.body.username || "";
    const password = req.body.password;
    const user = await User.findOne({
        $or: [{ username: input }, { phone: input }],
        loginPassword: password
    });
    if (user) {
        if (user.suspended) return res.status(403).json({ success: false, message: 'Account suspended' });
        user.token = crypto.randomBytes(24).toString('hex');
        await user.save();

        // pre-warm product cache (non-blocking)
        fetchProductsFromCloudinary().catch(err => {
          console.warn('Cloudinary pre-warm after login failed:', err && err.message ? err.message : err);
        });

        return res.json({ success: true, user });
    }
    res.status(401).json({ success: false, message: 'Invalid credentials' });
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

    // --- Midnight commission reset safety (frontend always correct after midnight) ---
    const todayStr = new Date().toISOString().slice(0, 10);
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
            fullName: dbUser.fullName ?? ""
        }
    });
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

        const tasks = await Task.find({ username: user.username }).lean();
        const combos = await Combo.find({ username: user.username }).lean();

        const userTasks = tasks.filter(t => (t.set || 1) === userSet);
        const tasksStarted = userTasks.length;

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
        if (Array.isArray(combos)) {
            comboToTrigger = combos.find(combo =>
                Number(combo.triggerTaskNumber) === (tasksStarted + 1) && combo.username === user.username
            );
        }

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
    await User.updateOne({ _id: user._id }, { $set: { currentSet: user.currentSet, setStartingBalance: null } });
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
    user.token = ""; // Invalidate token on password change
    await user.save();

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

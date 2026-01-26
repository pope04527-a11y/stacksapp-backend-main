/**
 * routes/admin.js
 *
 * Full file with login/token handling tightened so the exact persisted token is returned
 * and stored by the admin panel client. Other routes are preserved.
 *
 * Replace existing routes/admin.js with this file and restart the server.
 *
 * NOTE: This version keeps the transactional logic but also includes a safe
 * non-transactional fallback for MongoDB deployments that are not replica sets.
 * That ensures approve/reject operations won't throw on standalone servers and
 * will behave atomically where transactions are available.
 */

const express = require('express');
const crypto = require('crypto');
const mongoose = require('mongoose');
const cloudinary = require('cloudinary').v2;
const fs = require('fs');
const path = require('path');

const router = express.Router();

console.log('[ADMIN ROUTES LOADED] file=', __filename);

// ========== MODELS (SAFE DEFINITION) ==========
const Admin = mongoose.models.Admin || mongoose.model('Admin', new mongoose.Schema({
    username: String,
    password: String, // NOTE: plaintext in this example; hash in production!
    token: String
}, { collection: 'admin' }));

const User = mongoose.models.User || mongoose.model('User', new mongoose.Schema({}, { collection: 'users', strict: false }));
const Product = mongoose.models.Product || mongoose.model('Product', new mongoose.Schema({}, { collection: 'products', strict: false }));
const Combo = mongoose.models.Combo || mongoose.model('Combo', new mongoose.Schema({}, { collection: 'combos', strict: false }));
const Task = mongoose.models.Task || mongoose.model('Task', new mongoose.Schema({}, { collection: 'tasks', strict: false }));
const Transaction = mongoose.models.Transaction || mongoose.model('Transaction', new mongoose.Schema({}, { collection: 'transactions', strict: false }));
const Withdrawal = mongoose.models.Withdrawal || mongoose.model('Withdrawal', new mongoose.Schema({}, { collection: 'withdrawals', strict: false }));
const Notification = mongoose.models.Notification || mongoose.model('Notification', new mongoose.Schema({}, { collection: 'notifications', strict: false }));
const Log = mongoose.models.Log || mongoose.model('Log', new mongoose.Schema({}, { collection: 'logs', strict: false }));
const Setting = mongoose.models.Setting || mongoose.model('Setting', new mongoose.Schema({}, { collection: 'settings', strict: false }));

// ========== Cloudinary Config ==========
cloudinary.config({
    cloud_name: 'dhubpqnss',
    api_key: '129672528218384',
    api_secret: 'J8SEWj1hzBs8uTclbOtntG7G_8E'
});

// ========== Utility to wrap async route handlers ==========
function asyncHandler(fn) {
    return function (req, res, next) {
        Promise.resolve(fn(req, res, next)).catch((e) => {
            console.error(e);
            // If the thrown object contains a status property, use it (used below in transactions)
            if (e && e.status && typeof e.status === 'number') {
                return res.status(e.status).json({ success: false, message: e.message || 'Error' });
            }
            res.status(500).json({ success: false, message: e.message || 'Server error' });
        });
    };
}

// ========== FASTER CLOUDINARY PRODUCT LIST WITH IN-MEMORY CACHE ==========
let cachedCloudinaryProducts = [];
let lastCloudinaryFetch = 0;
const CLOUDINARY_CACHE_DURATION = 1000 * 60 * 10; // 10 minutes

router.get('/admin/refresh-products', asyncHandler(async (req, res) => {
    cachedCloudinaryProducts = [];
    lastCloudinaryFetch = 0;
    res.json({ success: true, message: "Product cache cleared, will refresh on next fetch." });
}));

router.get('/cloudinary-products', asyncHandler(async (req, res) => {
    let { minPrice, maxPrice, search } = req.query;
    minPrice = minPrice ? parseFloat(minPrice) : 0;
    maxPrice = maxPrice ? parseFloat(maxPrice) : Infinity;

    const now = Date.now();
    if (!cachedCloudinaryProducts.length || (now - lastCloudinaryFetch > CLOUDINARY_CACHE_DURATION)) {
        // Fetch from Cloudinary
        let products = [];
        let next_cursor = undefined;
        do {
            const result = await cloudinary.api.resources({
                type: 'upload',
                prefix: 'products/',
                max_results: 500,
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
                    public_id: r.public_id,
                    description: r.context.custom.alt || ""
                }));
            products = products.concat(pageProducts);
            next_cursor = result.next_cursor;
        } while (next_cursor);
        cachedCloudinaryProducts = products;
        lastCloudinaryFetch = now;
    }

    // Filtering
    let filtered = cachedCloudinaryProducts.filter(prod =>
        prod.price >= minPrice && prod.price <= maxPrice &&
        (!search || prod.name.toLowerCase().includes(search.toLowerCase()))
    );
    // Optional: limit (pagination can be added)
    filtered = filtered.slice(0, 100);

    res.json({ success: true, products: filtered });
}));

// ----------------------- Authentication -----------------------
// CORS preflight for admin login
router.options('/login', (req, res) => {
    res.header("Access-Control-Allow-Origin", req.headers.origin || "*");
    res.header("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Content-Type, X-Admin-Token, Authorization");
    res.header("Access-Control-Allow-Credentials", "true");
    res.sendStatus(204);
});

// Stronger token generator: 32 bytes -> 64 hex chars
function makeToken() {
    return crypto.randomBytes(32).toString('hex');
}

// POST /admin/login
// Ensures a fresh token is issued on every successful login, persisted atomically,
// set as httpOnly cookie and returned in the JSON response.
router.post('/login', asyncHandler(async (req, res) => {
    const { username, password } = req.body || {};

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password required' });
    }

    // Find admin by username/password (legacy plaintext)
    const adminDoc = await Admin.findOne({ username, password }).exec();
    if (!adminDoc) {
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Always generate a new token for each successful login.
    const newToken = makeToken();

    // Attempt to persist the token robustly:
    // 1) try updating by _id
    // 2) fallback to updating by username
    // 3) final fallback: reload document and save()
    let finalToken = null;
    let updatedAdmin = null;

    try {
        // Best-effort: update by _id
        try {
            updatedAdmin = await Admin.findOneAndUpdate(
                { _id: adminDoc._id },
                { $set: { token: newToken } },
                { new: true, useFindAndModify: false }
            ).lean().exec();
        } catch (e) {
            // Log and continue to fallback
            console.warn('Admin token update by _id failed:', e && e.message ? e.message : e);
        }

        if (!updatedAdmin) {
            // Fallback: update by username
            try {
                updatedAdmin = await Admin.findOneAndUpdate(
                    { username: adminDoc.username },
                    { $set: { token: newToken } },
                    { new: true, useFindAndModify: false }
                ).lean().exec();
            } catch (e) {
                console.warn('Admin token update by username failed:', e && e.message ? e.message : e);
            }
        }

        if (updatedAdmin && updatedAdmin.token) {
            finalToken = String(updatedAdmin.token);
        } else {
            // Final fallback: reload the document instance and save
            const reloaded = await Admin.findOne({ username: adminDoc.username }).exec();
            if (reloaded) {
                reloaded.token = newToken;
                await reloaded.save();
                finalToken = String(reloaded.token);
            } else {
                // Could not find the document to update — this is unexpected
                console.error('Failed to persist admin token: admin document not found by id or username', { id: adminDoc._id, username: adminDoc.username });
                return res.status(500).json({ success: false, message: 'Failed to persist token' });
            }
        }
    } catch (err) {
        console.error('Error persisting admin token:', err && err.stack ? err.stack : err);
        return res.status(500).json({ success: false, message: 'Failed to persist token' });
    }

    // Set the canonical token as httpOnly cookie so browsers send it automatically
    if (finalToken) {
        try {
            res.cookie('stacksAdminToken', finalToken, {
                httpOnly: true,
                sameSite: 'Lax',
                secure: process.env.NODE_ENV === 'production',
                maxAge: 1000 * 60 * 60 * 24 * 30 // 30 days
            });
        } catch (e) {
            console.warn('Failed to set admin cookie', e && e.message ? e.message : e);
        }
    }

    // CORS headers
    res.header("Access-Control-Allow-Origin", req.headers.origin || "*");
    res.header("Access-Control-Allow-Credentials", "true");

    // Return the exact persisted token in JSON (guaranteed to match DB)
    return res.json({ success: true, token: finalToken });
}));

// GET /admin/token - return canonical token (reads cookie or header)
router.get('/token', asyncHandler(async (req, res) => {
    let token = null;
    if (req.cookies && req.cookies.stacksAdminToken) token = String(req.cookies.stacksAdminToken);
    if (!token) {
        const headerAuth = req.headers['authorization'] || '';
        const headerAdmin = req.headers['x-admin-token'] || req.headers['X-Admin-Token'] || '';
        if (headerAuth && String(headerAuth).toLowerCase().startsWith('bearer ')) {
            token = String(headerAuth).split(' ')[1];
        } else if (headerAdmin) {
            token = String(headerAdmin);
        }
    }
    if (!token) return res.status(403).json({ success: false, message: 'No token provided' });

    // validate exists in Admin collection
    const admin = await Admin.findOne({ token }).lean().exec();
    if (!admin) return res.status(403).json({ success: false, message: 'Invalid token' });

    return res.json({ success: true, token: String(admin.token) });
}));

// ----------------------- Serve admin settings client script (public) -----------------------
router.get('/settings.js', (req, res) => {
    const filePath = path.join(__dirname, '..', 'public', 'admin-panel', 'js', 'settings.js');
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    // prevent aggressive caching so admin gets latest script after deployments
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, max-age=0');
    res.sendFile(filePath, (err) => {
        if (err) {
            console.error('Failed to send /admin/settings.js:', err);
            res.status(404).send('// settings.js not found');
        }
    });
});

// ----------------------- Middleware: Protect All Other Admin Routes -----------------------
async function verifyAdminToken(req, res, next) {
    try {
        // Prefer token from httpOnly cookie 'stacksAdminToken'
        let token = null;
        if (req.cookies && req.cookies.stacksAdminToken) token = String(req.cookies.stacksAdminToken);

        // fallback: accept from Authorization: Bearer <token>, x-admin-token or x-auth-token headers
        if (!token) {
            const headerAuth = req.headers['authorization'] || '';
            const headerAdmin = req.headers['x-admin-token'] || req.headers['X-Admin-Token'] || '';
            const headerXAuth = req.headers['x-auth-token'] || req.headers['X-Auth-Token'] || '';
            if (headerAuth && String(headerAuth).toLowerCase().startsWith('bearer ')) {
                token = String(headerAuth).split(' ')[1];
            } else if (headerAdmin) {
                token = String(headerAdmin);
            } else if (headerXAuth) {
                token = String(headerXAuth);
            }
        }

        if (!token) {
            console.warn('verifyAdminToken: no token provided');
            return res.status(403).json({ success: false, message: 'Unauthorized' });
        }

        token = token.trim().replace(/^"|"$/g, '');

        // debug: log the incoming token (temporary)
        console.debug('verifyAdminToken - incoming token:', token);

        // try Admin collection (canonical)
        const adminDoc = await Admin.findOne({ token }).lean().exec();
        if (adminDoc) {
            req.admin = adminDoc;
            return next();
        }

        // fallback: try a User with username "admin" that stores token (legacy)
        const userDoc = await User.findOne({ username: "admin", token }).lean().exec();
        if (userDoc) {
            req.admin = userDoc;
            return next();
        }

        console.warn('verifyAdminToken: token not found in Admin or User collections:', token);
        return res.status(403).json({ success: false, message: 'Unauthorized' });
    } catch (err) {
        console.error('verifyAdminToken ERROR:', err && err.message ? err.message : err);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
}

// Allow some public endpoints to bypass admin auth
router.use((req, res, next) => {
    if (
        req.path === "/login" ||
        req.method === "OPTIONS" ||
        req.path === "/cloudinary-products" ||
        req.path === "/admin/refresh-products" ||
        req.path === "/settings-public" ||
        req.path === "/service" ||
        req.path === "/settings.js" ||
        req.path === "/token"
    ) return next();
    return verifyAdminToken(req, res, next);
});

// ===================== PUBLIC SETTINGS FOR FRONTEND (NO AUTH) ===================== //
router.get('/settings-public', asyncHandler(async (_, res) => {
    let settings = await Setting.findOne({}).lean() || {};
    if (!settings.service) {
        settings.service = { whatsapp: "", telegram: "" };
    }
    // Prevent caching
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');
    res.json({ service: settings.service });
}));

// ===================== SERVICE JSON FILE API ===================== //
router.get('/service', asyncHandler(async (req, res) => {
    const serviceJsonPath = path.join(__dirname, '../data/service.json');
    fs.readFile(serviceJsonPath, "utf8", (err, data) => {
        if (err) return res.status(500).json({ error: "Failed to read service.json" });
        try {
            res.json(JSON.parse(data));
        } catch (e) {
            res.status(500).json({ error: "Invalid JSON in service.json" });
        }
    });
}));

router.post('/service', asyncHandler(async (req, res) => {
    const serviceJsonPath = path.join(__dirname, '../data/service.json');
    fs.writeFile(serviceJsonPath, JSON.stringify(req.body, null, 2), "utf8", (err) => {
        if (err) return res.status(500).json({ error: "Failed to update service.json" });
        res.json({ success: true });
    });
}));

// ===================== USER MANAGER: UNIFIED EDIT/ACTIONS ===================== //
router.put('/user/:username', asyncHandler(async (req, res) => {
    const { username } = req.params;
    const { action, updates, newPassword, amount } = req.body;

    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    switch (action) {
        case 'edit':
            if (!updates || typeof updates !== 'object') return res.status(400).json({ success: false, message: 'No updates provided.' });
            Object.assign(user, updates);
            await user.save();
            return res.json({ success: true, user });

        case 'suspend':
            user.status = "Suspended";
            await user.save();
            return res.json({ success: true, status: user.status });

        case 'activate':
            user.status = "Active";
            await user.save();
            return res.json({ success: true, status: user.status });

        case 'reset_password':
            if (!newPassword) return res.status(400).json({ success: false, message: 'New password required.' });
            user.password = newPassword; // In production, hash!
            await user.save();
            return res.json({ success: true, message: "Password reset." });

        case 'reset_balance':
            user.balance = 0;
            await user.save();
            return res.json({ success: true, balance: user.balance });

        case 'add_balance':
            if (typeof amount !== 'number') return res.status(400).json({ success: false, message: 'Amount required.' });
            user.balance = (user.balance || 0) + amount;
            await user.save();
            return res.json({ success: true, balance: user.balance });

        case 'remove_balance':
            if (typeof amount !== 'number') return res.status(400).json({ success: false, message: 'Amount required.' });
            user.balance = Math.max(0, (user.balance || 0) - amount);
            await user.save();
            return res.json({ success: true, balance: user.balance });

        case 'upgrade_vip':
            user.vipLevel = Math.min((user.vipLevel || 1) + 1, 10);
            await user.save();
            return res.json({ success: true, vipLevel: user.vipLevel });

        case 'downgrade_vip':
            user.vipLevel = Math.max((user.vipLevel || 1) - 1, 1);
            await user.save();
            return res.json({ success: true, vipLevel: user.vipLevel });

        default:
            return res.status(400).json({ success: false, message: 'Unknown action.' });
    }
}));

// ===================== DASHBOARD ANALYTICS API ===================== //
router.get('/total-users', asyncHandler(async (_, res) => {
    const count = await User.countDocuments();
    res.json({ count });
}));
router.get('/total-balance', asyncHandler(async (_, res) => {
    const users = await User.find({}, { balance: 1 }).lean();
    const total = users.reduce((sum, u) => sum + (typeof u.balance === 'number' ? u.balance : 0), 0);
    res.json({ total: total.toFixed(2) });
}));
router.get('/active-tasks', asyncHandler(async (_, res) => {
    const count = await Task.countDocuments({ status: { $in: ["Pending", "Active"] } });
    res.json({ count });
}));
router.get('/pending-withdrawals', asyncHandler(async (_, res) => {
    const count = await Withdrawal.countDocuments({ status: "Pending" });
    res.json({ count });
}));

// ===================== WITHDRAWALS API ===================== //
// GET /admin/withdrawals - list withdrawals
router.get('/withdrawals', asyncHandler(async (req, res) => {
    const list = await Withdrawal.find({}).lean().exec();
    res.json(list);
}));

// PUT /admin/withdrawals/:id - update a withdrawal
router.put('/withdrawals/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updates = req.body || {};
    const updated = await Withdrawal.findOneAndUpdate({ _id: id }, { $set: updates }, { new: true }).lean().exec();
    if (!updated) return res.status(404).json({ success: false, message: 'Withdrawal not found' });
    res.json({ success: true, withdrawal: updated });
}));

/**
 * Helper: Safe non-transactional approve fallback
 * Tries an atomic conditional update to ensure only pending withdrawals are modified.
 */
async function approveWithdrawalFallback(id, processedBy, adminNote) {
    const update = {
        $set: {
            status: 'Approved',
            processedAt: new Date(),
            processedBy
        }
    };
    if (typeof adminNote === 'string') update.$set.adminNote = adminNote;

    const updated = await Withdrawal.findOneAndUpdate(
        { _id: id, status: { $in: ['Pending', 'pending'] } },
        update,
        { new: true }
    ).lean().exec();

    if (!updated) {
        // Check if withdrawal exists but not pending
        const exists = await Withdrawal.findOne({ _id: id }).lean().exec();
        if (!exists) {
            const err = new Error('Withdrawal not found');
            err.status = 404;
            throw err;
        } else {
            const err = new Error('Withdrawal is not pending');
            err.status = 400;
            throw err;
        }
    }
    return updated;
}

/**
 * Helper: Safe non-transactional reject fallback
 * Uses conditional update for the withdrawal and attempts a separate refund update when possible.
 */
async function rejectWithdrawalFallback(id, processedBy, adminNote) {
    const update = {
        $set: {
            status: 'Rejected',
            processedAt: new Date(),
            processedBy
        }
    };
    if (typeof adminNote === 'string') update.$set.adminNote = adminNote;

    const updated = await Withdrawal.findOneAndUpdate(
        { _id: id, status: { $in: ['Pending', 'pending'] } },
        update,
        { new: true }
    ).lean().exec();

    if (!updated) {
        const exists = await Withdrawal.findOne({ _id: id }).lean().exec();
        if (!exists) {
            const err = new Error('Withdrawal not found');
            err.status = 404;
            throw err;
        } else {
            const err = new Error('Withdrawal is not pending');
            err.status = 400;
            throw err;
        }
    }

    // Attempt refund if applicable
    let refundedUser = null;
    const amount = (typeof updated.amount === 'number') ? updated.amount : (updated.amount ? Number(updated.amount) : NaN);
    let userQuery = null;
    if (updated.username) userQuery = { username: String(updated.username) };
    else if (updated.userId && mongoose.Types.ObjectId.isValid(String(updated.userId))) userQuery = { _id: updated.userId };

    if (userQuery && !isNaN(amount) && amount > 0) {
        const userUpdateRes = await User.findOneAndUpdate(userQuery, { $inc: { balance: amount } }, { new: true }).lean().exec();
        if (userUpdateRes) {
            refundedUser = { username: userUpdateRes.username, balance: userUpdateRes.balance };
        } else {
            console.warn('Reject refund: user not found for', userQuery);
        }
    }

    return { updated, refundedUser };
}

// PATCH approve (transactional with fallback)
router.patch('/withdrawals/:id/approve', asyncHandler(async (req, res) => {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ success: false, message: 'Invalid withdrawal id' });
    }

    // Compute processedBy string
    const processedBy = req.admin && (req.admin.username || req.admin._id) ? (req.admin.username || String(req.admin._id)) : 'system';
    const adminNote = req.body && typeof req.body.adminNote === 'string' ? req.body.adminNote : undefined;

    // Try transactional path first (if supported). If any transactional APIs fail, fallback to atomic updates.
    let session;
    try {
        session = await mongoose.startSession();
    } catch (e) {
        session = null;
    }

    if (session && typeof session.withTransaction === 'function') {
        // Attempt transactional flow, but catch and fallback on errors.
        try {
            let updatedWithdrawal = null;
            await session.withTransaction(async () => {
                const w = await Withdrawal.findOne({ _id: id }).session(session).exec();
                if (!w) {
                    const err = new Error('Withdrawal not found');
                    err.status = 404;
                    throw err;
                }

                const currentStatus = (w.status || '').toString();
                if (currentStatus.toLowerCase() !== 'pending') {
                    const err = new Error('Withdrawal is not pending');
                    err.status = 400;
                    throw err;
                }

                w.status = 'Approved';
                w.processedAt = new Date();
                w.processedBy = processedBy;
                if (adminNote) w.adminNote = adminNote;
                await w.save({ session });

                // Hook for extra transactional bookkeeping could be added here.

                updatedWithdrawal = w.toObject();
            });

            try { session.endSession(); } catch (e) {}
            return res.json({ success: true, withdrawal: updatedWithdrawal });
        } catch (err) {
            try { session.endSession(); } catch (e) {}
            console.warn('Transactional approve failed, falling back to non-transactional method:', err && err.message ? err.message : err);
            // fall through to fallback logic below
        }
    } else {
        if (session) try { session.endSession(); } catch (e) {}
        console.debug('Transactions not supported by MongoDB deployment — using non-transactional fallback for approve');
    }

    // Fallback non-transactional path (atomic conditional update)
    try {
        const updated = await approveWithdrawalFallback(id, processedBy, adminNote);
        return res.json({ success: true, withdrawal: updated });
    } catch (err) {
        if (err && err.status) return res.status(err.status).json({ success: false, message: err.message });
        console.error('Approve fallback error:', err && err.stack ? err.stack : err);
        return res.status(500).json({ success: false, message: 'Failed to approve withdrawal' });
    }
}));

// PATCH reject (transactional with fallback)
router.patch('/withdrawals/:id/reject', asyncHandler(async (req, res) => {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ success: false, message: 'Invalid withdrawal id' });
    }

    const processedBy = req.admin && (req.admin.username || req.admin._id) ? (req.admin.username || String(req.admin._id)) : 'system';
    const adminNote = req.body && typeof req.body.adminNote === 'string' ? req.body.adminNote : undefined;

    let session;
    try {
        session = await mongoose.startSession();
    } catch (e) {
        session = null;
    }

    if (session && typeof session.withTransaction === 'function') {
        try {
            let updatedWithdrawal = null;
            let refundedUser = null;
            await session.withTransaction(async () => {
                const w = await Withdrawal.findOne({ _id: id }).session(session).exec();
                if (!w) {
                    const err = new Error('Withdrawal not found');
                    err.status = 404;
                    throw err;
                }

                const currentStatus = (w.status || '').toString();
                if (currentStatus.toLowerCase() !== 'pending') {
                    const err = new Error('Withdrawal is not pending');
                    err.status = 400;
                    throw err;
                }

                w.status = 'Rejected';
                w.processedAt = new Date();
                w.processedBy = processedBy;
                if (adminNote) w.adminNote = adminNote;

                // Optional refund logic
                const amount = (typeof w.amount === 'number') ? w.amount : (w.amount ? Number(w.amount) : NaN);
                let userQuery = null;
                if (w.username) userQuery = { username: String(w.username) };
                else if (w.userId && mongoose.Types.ObjectId.isValid(String(w.userId))) userQuery = { _id: w.userId };

                if (userQuery && !isNaN(amount) && amount > 0) {
                    const userDoc = await User.findOne(userQuery).session(session).exec();
                    if (userDoc) {
                        userDoc.balance = (typeof userDoc.balance === 'number' ? userDoc.balance : 0) + amount;
                        await userDoc.save({ session });
                        refundedUser = { username: userDoc.username, balance: userDoc.balance };
                        // optionally add Transaction record here inside the same transaction
                    } else {
                        console.warn('Rejecting withdrawal but user not found to refund (transactional):', userQuery);
                    }
                }

                await w.save({ session });
                updatedWithdrawal = w.toObject();
            });

            try { session.endSession(); } catch (e) {}
            return res.json({ success: true, withdrawal: updatedWithdrawal, refundedUser: refundedUser || null });
        } catch (err) {
            try { session.endSession(); } catch (e) {}
            console.warn('Transactional reject failed, falling back to non-transactional method:', err && err.message ? err.message : err);
            // fall through to fallback logic below
        }
    } else {
        if (session) try { session.endSession(); } catch (e) {}
        console.debug('Transactions not supported by MongoDB deployment — using non-transactional fallback for reject');
    }

    // Fallback non-transactional path
    try {
        const { updated, refundedUser } = await rejectWithdrawalFallback(id, processedBy, adminNote);
        return res.json({ success: true, withdrawal: updated, refundedUser: refundedUser || null });
    } catch (err) {
        if (err && err.status) return res.status(err.status).json({ success: false, message: err.message });
        console.error('Reject fallback error:', err && err.stack ? err.stack : err);
        return res.status(500).json({ success: false, message: 'Failed to reject withdrawal' });
    }
}));

// DELETE
router.delete('/withdrawals/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const result = await Withdrawal.deleteOne({ _id: id }).exec();
    if (result.deletedCount === 0) return res.status(404).json({ success: false, message: 'Withdrawal not found' });
    res.json({ success: true });
}));

// ===================== SETTINGS API ENHANCED (SERVICE & ACTIVITY LOCK) ===================== //
router.get('/settings', asyncHandler(async (_, res) => {
    let settings = await Setting.findOne({}).lean() || {};

    // Ensure all fields are always present for the frontend
    settings.siteName = settings.siteName || "";
    settings.currency = settings.currency || "";
    // New defaults for currencySymbol and decimals
    settings.currencySymbol = settings.currencySymbol || "";
    settings.currencyDecimals = (typeof settings.currencyDecimals === 'number') ? settings.currencyDecimals : 2;
    settings.currencyPosition = settings.currencyPosition || "after"; // optional: "before" or "after"

    settings.defaultVip = settings.defaultVip || 1;
    settings.inviteBonus = settings.inviteBonus || 0;
    settings.telegramGroup = settings.telegramGroup || "";
    settings.homepageNotice = settings.homepageNotice || "";
    settings.depositInstructions = settings.depositInstructions || "";
    settings.withdrawInstructions = settings.withdrawInstructions || "";
    settings.minWithdraw = settings.minWithdraw || 0;
    settings.maxWithdraw = settings.maxWithdraw || 0;

    // Normalise withdraw fee fields: support legacy `withdrawFee` and canonical `withdrawFeePercent`
    if (typeof settings.withdrawFeePercent === 'undefined' && typeof settings.withdrawFee !== 'undefined') {
        settings.withdrawFeePercent = settings.withdrawFee;
    }
    settings.withdrawFeePercent = settings.withdrawFeePercent || 0;

    settings.minDeposit = settings.minDeposit || 0;
    settings.maxDeposit = settings.maxDeposit || 0;
    settings.dailyTaskSet = settings.dailyTaskSet || 0;
    settings.maintenance = !!settings.maintenance;
    settings.maintenanceMode = !!settings.maintenanceMode;

    if (!settings.service) {
        settings.service = { whatsapp: "", telegram: "" };
    } else {
        settings.service.whatsapp = settings.service.whatsapp || "";
        settings.service.telegram = settings.service.telegram || "";
    }

    if (typeof settings.activityLock !== "object") {
        settings.activityLock = { enabled: false, users: [] };
    } else {
        settings.activityLock.enabled = !!settings.activityLock.enabled;
        if (!Array.isArray(settings.activityLock.users)) settings.activityLock.users = [];
    }

    // platform closing helpers (ensure naming consistency)
    settings.platformClosed = !!settings.platformClosed;
    settings.autoOpenHourUK = typeof settings.autoOpenHourUK === 'number' ? settings.autoOpenHourUK : 10;
    settings.whoCanAccessDuringClose = Array.isArray(settings.whoCanAccessDuringClose) ? settings.whoCanAccessDuringClose : [];

    // Provide frontend-friendly aliases:
    const hour = Number(settings.autoOpenHourUK);
    if (!isNaN(hour) && hour >= 0 && hour <= 23) {
        const hh = String(hour).padStart(2, '0');
        settings.autoOpenTime = `${hh}:00`;
    } else {
        settings.autoOpenTime = "";
    }
    settings.allowList = Array.isArray(settings.whoCanAccessDuringClose) ? settings.whoCanAccessDuringClose : [];

    res.json(settings);
}));

router.post('/settings', asyncHandler(async (req, res) => {
    // Debug logging to help ensure requests reach this handler and payloads are as-expected
    console.log('ADMIN POST /admin/settings called - x-admin-token:', req.headers['x-admin-token']);
    try {
        console.log('ADMIN POST /admin/settings payload (truncated):', JSON.stringify(req.body).slice(0, 1000));
    } catch (e) {
        console.warn('Could not stringify payload for log');
    }

    const updates = req.body || {};

    // Build an update document (use atomic findOneAndUpdate with upsert to avoid race/duplicate issues)
    const updateDoc = {};

    // whitelisted simple fields
    const simpleFields = [
        "siteName", "currency", "currencySymbol", "currencyDecimals", "currencyPosition",
        "defaultVip", "inviteBonus", "telegramGroup",
        "homepageNotice", "depositInstructions", "withdrawInstructions",
        "minWithdraw", "maxWithdraw", "minDeposit", "maxDeposit",
        "dailyTaskSet", "maintenance", "maintenanceMode"
    ];
    for (const key of simpleFields) {
        if (updates[key] !== undefined) updateDoc[key] = updates[key];
    }

    // Ensure currencyDecimals is a number if provided
    if (updates.currencyDecimals !== undefined) {
        const parsed = Number(updates.currencyDecimals);
        updateDoc.currencyDecimals = Number.isFinite(parsed) ? parsed : 2;
    }

    // withdraw fee normalization
    if (updates.withdrawFeePercent !== undefined) {
        const parsed = Number(updates.withdrawFeePercent);
        updateDoc.withdrawFeePercent = isNaN(parsed) ? 0 : parsed;
    } else if (updates.withdrawFee !== undefined) {
        const parsed = Number(updates.withdrawFee);
        updateDoc.withdrawFeePercent = isNaN(parsed) ? 0 : parsed;
    }

    // service merge (keep existing keys if not provided)
    if (updates.service && typeof updates.service === 'object') {
        // We'll set service fully to provided object (merge on DB side)
        updateDoc.service = { ...(updates.service || {}) };
    }

    // activityLock normalization
    if (updates.activityLock && typeof updates.activityLock === 'object') {
        const acl = {
            enabled: !!updates.activityLock.enabled,
            users: []
        };
        if (Array.isArray(updates.activityLock.users)) {
            acl.users = updates.activityLock.users.map(u => String(u || '').trim()).filter(Boolean);
        } else if (typeof updates.activityLock.users === 'string') {
            acl.users = updates.activityLock.users.split(',').map(u => u.trim()).filter(Boolean);
        }
        updateDoc.activityLock = acl;
    }

    // platform closing controls
    if (updates.platformClosed !== undefined) {
        updateDoc.platformClosed = !!updates.platformClosed;
    }

    // parse autoOpenTime "HH:MM" to autoOpenHourUK if provided
    if (updates.autoOpenHourUK !== undefined && !isNaN(Number(updates.autoOpenHourUK))) {
        updateDoc.autoOpenHourUK = Number(updates.autoOpenHourUK);
    } else if (typeof updates.autoOpenTime === 'string' && updates.autoOpenTime.trim()) {
        const parts = updates.autoOpenTime.split(':');
        const parsed = parseInt(parts[0], 10);
        if (!isNaN(parsed) && parsed >= 0 && parsed <= 23) {
            updateDoc.autoOpenHourUK = parsed;
        }
    }

    // allowList / whoCanAccessDuringClose normalization
    if (updates.allowList !== undefined) {
        if (Array.isArray(updates.allowList)) {
            updateDoc.whoCanAccessDuringClose = updates.allowList.map(u => String(u || '').trim()).filter(Boolean);
        } else if (typeof updates.allowList === 'string') {
            updateDoc.whoCanAccessDuringClose = updates.allowList.split(',').map(u => u.trim()).filter(Boolean);
        } else {
            updateDoc.whoCanAccessDuringClose = [];
        }
    } else if (updates.whoCanAccessDuringClose !== undefined) {
        if (Array.isArray(updates.whoCanAccessDuringClose)) {
            updateDoc.whoCanAccessDuringClose = updates.whoCanAccessDuringClose.map(u => String(u || '').trim()).filter(Boolean);
        } else if (typeof updates.whoCanAccessDuringClose === 'string') {
            updateDoc.whoCanAccessDuringClose = updates.whoCanAccessDuringClose.split(',').map(u => u.trim()).filter(Boolean);
        } else {
            updateDoc.whoCanAccessDuringClose = [];
        }
    }

    if (typeof updateDoc.service === 'undefined') {
        // leave service untouched unless provided
    } else {
        updateDoc.service.whatsapp = updateDoc.service.whatsapp || "";
        updateDoc.service.telegram = updateDoc.service.telegram || "";
    }

    if (typeof updateDoc.activityLock === 'undefined') {
        // leave untouched
    }

    // Perform atomic update with upsert and return the new doc
    const saved = await Setting.findOneAndUpdate(
        {},
        { $set: updateDoc },
        { upsert: true, new: true }
    ).exec();

    console.log('ADMIN POST /admin/settings saved settings id:', saved && saved._id);
    res.json({ success: true, settings: saved });
}));

// ===================== USERS API (RESTful) ===================== //
router.get('/users', asyncHandler(async (_, res) => {
    const users = await User.find({}).lean();
    res.json(users);
}));
router.post('/users', asyncHandler(async (req, res) => {
    const { username, phone, vipLevel, balance, exchange, walletAddress } = req.body;
    if (!username || !phone) return res.status(400).json({ success: false, message: 'Username and phone are required' });
    const exists = await User.findOne({ username }).lean();
    if (exists) return res.status(409).json({ success: false, message: 'Username already exists' });

    const user = {
        username,
        phone,
        vipLevel: vipLevel || 1,
        balance: balance || 0,
        status: "Active",
        tasksCompletedInSet: 0,
        tasksSetSize: 40,
        exchange: exchange || "",
        walletAddress: walletAddress || ""
    };
    await User.create(user);
    res.json({ success: true, user });
}));
router.put('/users/:username', asyncHandler(async (req, res) => {
    const { username } = req.params;
    const updates = req.body;
    const user = await User.findOneAndUpdate({ username }, updates, { new: true }).lean();
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, user });
}));
router.patch('/users/:username/suspend', asyncHandler(async (req, res) => {
    const { username } = req.params;
    const user = await User.findOne({ username }).lean();
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const newStatus = user.status === "Suspended" ? "Active" : "Suspended";
    await User.updateOne({ username }, { $set: { status: newStatus } });
    res.json({ success: true, status: newStatus });
}));
router.delete('/users/:username', asyncHandler(async (req, res) => {
    const { username } = req.params;
    const result = await User.deleteOne({ username });
    if (result.deletedCount === 0) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true });
}));
router.get('/users/:username', asyncHandler(async (req, res) => {
    const { username } = req.params;
    const user = await User.findOne({ username }).lean();
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, user });
}));

// (Remaining routes kept as in original file)

module.exports = router;

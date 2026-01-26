const express = require('express');
const crypto = require('crypto');
const mongoose = require('mongoose');
const cloudinary = require('cloudinary').v2;
const fs = require('fs');
const path = require('path');

const router = express.Router();

// ========== MODELS (SAFE DEFINITION) ==========
const Admin = mongoose.models.Admin || mongoose.model('Admin', new mongoose.Schema({
    username: String,
    password: String, // Hash in production!
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
            const pageProducts = result.resources
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
router.options('/login', (req, res) => {
    res.header("Access-Control-Allow-Origin", req.headers.origin || "*");
    res.header("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Content-Type, X-Admin-Token");
    res.header("Access-Control-Allow-Credentials", "true");
    res.sendStatus(204);
});
router.post('/login', asyncHandler(async (req, res) => {
    const { username, password } = req.body;
    const admin = await Admin.findOne({ username, password }).lean();
    if (admin) {
        const token = crypto.randomBytes(24).toString('hex');
        await Admin.updateOne({ _id: admin._id }, { $set: { token } });
        res.header("Access-Control-Allow-Origin", req.headers.origin || "*");
        res.header("Access-Control-Allow-Credentials", "true");
        return res.json({ success: true, token });
    }
    res.status(401).json({ success: false, message: 'Invalid credentials' });
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
    const token = req.headers['x-admin-token'];
    // --------- UPDATED: Accept token from users collection for admin user as well ---------
    let admin = await Admin.findOne({ token }).lean();
    if (!admin) {
        admin = await User.findOne({ username: "admin", token }).lean();
    }
    if (token && admin) return next();
    console.warn('verifyAdminToken: unauthorized request, x-admin-token=', token);
    return res.status(403).json({ success: false, message: 'Unauthorized' });
}
router.use((req, res, next) => {
    // Allow settings-public as a public endpoint and allow the admin client script
    if (
        req.path === "/login" ||
        req.method === "OPTIONS" ||
        req.path === "/cloudinary-products" ||
        req.path === "/admin/refresh-products" ||
        req.path === "/settings-public" ||
        req.path === "/service" ||
        req.path === "/settings.js"
    ) return next();
    return verifyAdminToken(req, res, next);
});

// ===================== PUBLIC SETTINGS FOR FRONTEND (NO AUTH) ===================== //
router.get('/settings-public', asyncHandler(async (_, res) => {
    let settings = await Setting.findOne({}).lean() || {};

    // Provide a compact, safe public view for the frontend
    const publicSettings = {
        service: settings.service || { whatsapp: "", telegram: "" },
        // currency info for frontend display/formatting
        currency: settings.currency || "",
        currencySymbol: settings.currencySymbol || "",
        currencyDecimals: (typeof settings.currencyDecimals === 'number') ? settings.currencyDecimals : 2
    };

    // Prevent Netlify/Browser from caching
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');
    res.json(publicSettings);
}));

// ===================== SERVICE JSON FILE API ===================== //
// GET service.json
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

// UPDATE service.json
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
    // - autoOpenTime: "HH:00" derived from autoOpenHourUK so <input type="time"> can be populated
    // - allowList: alias for whoCanAccessDuringClose
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

    // Ensure some defaults are set if absent (do not overwrite existing DB keys unnecessarily)
    // We'll rely on upsert to create missing document with provided defaults where needed
    if (typeof updateDoc.service === 'undefined') {
        // leave service untouched unless provided
    } else {
        // ensure keys exist
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

router.post('/reset-user-task-set', asyncHandler(async (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ success: false, message: 'Username is required' });
    const userDoc = await User.findOne({ username });
    const newSet = (userDoc && typeof userDoc.currentSet === 'number') ? userDoc.currentSet + 1 : 2;
    const user = await User.findOneAndUpdate({ username }, { $set: { tasksCompletedInSet: 0, currentSet: newSet } }, { new: true }).lean();
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, message: 'Task progress and set reset for user.' });
}));

router.post('/reset-user-task-progress', asyncHandler(async (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ success: false, message: 'Username is required' });
    const user = await User.findOneAndUpdate({ username }, { $set: { tasksCompletedInSet: 0 } }, { new: true }).lean();
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, message: 'Task progress reset for user.' });
}));

router.post('/vip/bulk-upgrade', asyncHandler(async (req, res) => {
    const { usernames } = req.body;
    if (!Array.isArray(usernames) || !usernames.length)
        return res.status(400).json({ success: false, message: 'Usernames required.' });
    const users = await User.find({ username: { $in: usernames } });
    let changed = 0;
    for (const user of users) {
        if (typeof user.vipLevel === 'number') {
            user.vipLevel = Math.min(user.vipLevel + 1, 10);
            await user.save();
            changed++;
        }
    }
    res.json({ success: true, changed });
}));
router.post('/vip/bulk-downgrade', asyncHandler(async (req, res) => {
    const { usernames } = req.body;
    if (!Array.isArray(usernames) || !usernames.length)
        return res.status(400).json({ success: false, message: 'Usernames required.' });
    const users = await User.find({ username: { $in: usernames } });
    let changed = 0;
    for (const user of users) {
        if (typeof user.vipLevel === 'number') {
            user.vipLevel = Math.max(user.vipLevel - 1, 1);
            await user.save();
            changed++;
        }
    }
    res.json({ success: true, changed });
}));

router.get('/products', asyncHandler(async (_, res) => {
    const products = await Product.find({}).lean();
    res.json(products);
}));
router.post('/products', asyncHandler(async (req, res) => {
    const { name, description, price, image } = req.body;
    if (!name) return res.status(400).json({ success: false, message: 'Product name is required' });
    const exists = await Product.findOne({ name }).lean();
    if (exists) return res.status(409).json({ success: false, message: 'Product already exists' });
    const product = {
        name,
        description: description || "",
        price: price || 0,
        image: image || "",
        status: "Active"
    };
    await Product.create(product);
    res.json({ success: true, product });
}));
router.put('/products/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updates = req.body;
    const product = await Product.findByIdAndUpdate(id, updates, { new: true }).lean();
    if (!product) return res.status(404).json({ success: false, message: 'Product not found' });
    res.json({ success: true, product });
}));
router.patch('/products/:id/disable', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const product = await Product.findById(id).lean();
    if (!product) return res.status(404).json({ success: false, message: 'Product not found' });
    const newStatus = product.status === "Suspended" ? "Active" : "Suspended";
    await Product.updateOne({ _id: id }, { $set: { status: newStatus } });
    res.json({ success: true, status: newStatus });
}));
router.delete('/products/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const result = await Product.deleteOne({ _id: id });
    if (result.deletedCount === 0) return res.status(404).json({ success: false, message: 'Product not found' });
    res.json({ success: true });
}));
router.get('/products/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const product = await Product.findById(id).lean();
    if (!product) return res.status(404).json({ success: false, message: 'Product not found' });
    res.json({ success: true, product });
}));

router.get('/combos', asyncHandler(async (_, res) => {
    const combos = await Combo.find({}).lean();
    res.json(combos);
}));
router.post('/combos', asyncHandler(async (req, res) => {
    const { username, triggerTaskNumber, products } = req.body;
    if (!username || !triggerTaskNumber || !products || !Array.isArray(products) || products.length === 0)
        return res.status(400).json({ success: false, message: 'All fields required and at least one product.' });
    const combo = {
        username,
        triggerTaskNumber,
        products
    };
    await Combo.create(combo);
    res.json({ success: true, combo });
}));
router.put('/combos/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;
    if (!id || !mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ success: false, message: 'Invalid combo id' });
    }
    const { username, triggerTaskNumber, products } = req.body;
    const combo = await Combo.findById(id);
    if (!combo) return res.status(404).json({ success: false, message: 'Combo not found' });
    if (username) combo.username = username;
    if (triggerTaskNumber) combo.triggerTaskNumber = triggerTaskNumber;
    if (products && Array.isArray(products)) combo.products = products;
    await combo.save();
    res.json({ success: true, combo });
}));
router.delete('/combos/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;
    if (!id || !mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ success: false, message: 'Invalid combo id' });
    }
    const result = await Combo.deleteOne({ _id: id });
    if (result.deletedCount === 0) return res.status(404).json({ success: false, message: 'Combo not found' });
    res.json({ success: true });
}));
router.get('/combos/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;
    if (!id || !mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ success: false, message: 'Invalid combo id' });
    }
    const combo = await Combo.findById(id).lean();
    if (!combo) return res.status(404).json({ success: false, message: 'Combo not found' });
    res.json({ success: true, combo });
}));

router.get('/tasks', asyncHandler(async (_, res) => {
    const tasks = await Task.find({}).lean();
    res.json(tasks);
}));
router.post('/tasks', asyncHandler(async (req, res) => {
    const { user, name, status } = req.body;
    if (!user || !name) return res.status(400).json({ success: false, message: 'User and Task Name are required' });
    const task = {
        user,
        name,
        status: status || "Pending",
        createdAt: new Date().toISOString()
    };
    await Task.create(task);
    res.json({ success: true, task });
}));
router.put('/tasks/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updates = req.body;
    const task = await Task.findByIdAndUpdate(id, updates, { new: true }).lean();
    if (!task) return res.status(404).json({ success: false, message: 'Task not found' });
    res.json({ success: true, task });
}));
router.patch('/tasks/:id/complete', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const task = await Task.findById(id).lean();
    if (!task) return res.status(404).json({ success: false, message: 'Task not found' });
    await Task.updateOne({ _id: id }, { $set: { status: "Completed" } });
    res.json({ success: true, status: "Completed" });
}));
router.delete('/tasks/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const result = await Task.deleteOne({ _id: id });
    if (result.deletedCount === 0) return res.status(404).json({ success: false, message: 'Task not found' });
    res.json({ success: true });
}));
router.get('/tasks/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const task = await Task.findById(id).lean();
    if (!task) return res.status(404).json({ success: false, message: 'Task not found' });
    res.json({ success: true, task });
}));

router.get('/transactions', asyncHandler(async (_, res) => {
    const deposits = await Transaction.find({}).lean();
    const withdrawals = await Withdrawal.find({}).lean();
    res.json({ deposits, withdrawals });
}));
router.put('/transactions/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updates = req.body;
    const txn = await Transaction.findByIdAndUpdate(id, updates, { new: true }).lean();
    if (!txn) return res.status(404).json({ success: false, message: 'Transaction not found' });
    res.json({ success: true, transaction: txn });
}));
router.delete('/transactions/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const result = await Transaction.deleteOne({ _id: id });
    if (result.deletedCount === 0) return res.status(404).json({ success: false, message: 'Transaction not found' });
    res.json({ success: true });
}));
router.get('/transactions/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const txn = await Transaction.findById(id).lean();
    if (!txn) return res.status(404).json({ success: false, message: 'Transaction not found' });
    res.json({ success: true, transaction: txn });
}));

router.get('/withdrawals', asyncHandler(async (_, res) => {
    const withdrawals = await Withdrawal.find({}).lean();
    res.json(withdrawals);
}));
router.put('/withdrawals/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updates = req.body;
    const withdrawal = await Withdrawal.findByIdAndUpdate(id, updates, { new: true }).lean();
    if (!withdrawal) return res.status(404).json({ success: false, message: 'Withdrawal not found' });
    res.json({ success: true, withdrawal });
}));
router.patch('/withdrawals/:id/approve', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const withdrawal = await Withdrawal.findById(id).lean();
    if (!withdrawal) return res.status(404).json({ success: false, message: 'Withdrawal not found' });
    await Withdrawal.updateOne({ _id: id }, { $set: { status: "Approved" } });
    res.json({ success: true, status: "Approved" });
}));
router.patch('/withdrawals/:id/reject', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const withdrawal = await Withdrawal.findById(id).lean();
    if (!withdrawal) return res.status(404).json({ success: false, message: 'Withdrawal not found' });
    await Withdrawal.updateOne({ _id: id }, { $set: { status: "Rejected" } });
    res.json({ success: true, status: "Rejected" });
}));
router.delete('/withdrawals/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const result = await Withdrawal.deleteOne({ _id: id });
    if (result.deletedCount === 0) return res.status(404).json({ success: false, message: 'Withdrawal not found' });
    res.json({ success: true });
}));
router.get('/withdrawals/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const withdrawal = await Withdrawal.findById(id).lean();
    if (!withdrawal) return res.status(404).json({ success: false, message: 'Withdrawal not found' });
    res.json({ success: true, withdrawal });
}));

router.get('/notifications', asyncHandler(async (_, res) => {
    const notifications = await Notification.find({}).lean();
    res.json(notifications);
}));
router.post('/notifications', asyncHandler(async (req, res) => {
    const { title, message, status, recipients } = req.body;
    if (!title || !message) return res.status(400).json({ success: false, message: 'Title and message are required' });
    const notification = {
        title,
        message,
        status: status || "Active",
        recipients: recipients && Array.isArray(recipients) && recipients.length > 0
            ? recipients
            : ["all"],
        createdAt: new Date().toISOString()
    };
    await Notification.create(notification);
    res.json({ success: true, notification });
}));
router.put('/notifications/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updates = req.body;
    const notification = await Notification.findByIdAndUpdate(id, updates, { new: true }).lean();
    if (!notification) return res.status(404).json({ success: false, message: 'Notification not found' });
    res.json({ success: true, notification });
}));
router.patch('/notifications/:id/deactivate', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const notification = await Notification.findById(id).lean();
    if (!notification) return res.status(404).json({ success: false, message: 'Notification not found' });
    await Notification.updateOne({ _id: id }, { $set: { status: "Inactive" } });
    res.json({ success: true, status: "Inactive" });
}));
router.delete('/notifications/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const result = await Notification.deleteOne({ _id: id });
    if (result.deletedCount === 0) return res.status(404).json({ success: false, message: 'Notification not found' });
    res.json({ success: true });
}));
router.get('/notifications/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const notification = await Notification.findById(id).lean();
    if (!notification) return res.status(404).json({ success: false, message: 'Notification not found' });
    res.json({ success: true, notification });
}));

router.get('/user/:username/notifications', asyncHandler(async (req, res) => {
    const { username } = req.params;
    const notifications = await Notification.find({
        $or: [
            { recipients: "all" },
            { recipients: username }
        ]
    }).lean();
    res.json(notifications);
}));

router.post('/update-vip', asyncHandler(async (req, res) => {
    const { username, vip } = req.body;
    const user = await User.findOneAndUpdate({ username }, { $set: { vipLevel: vip } }, { new: true }).lean();
    if (!user) return res.status(404).json({ success: false });
    res.json({ success: true });
}));

// ======= FIXED add-balance: ensure userId is included in Transaction to satisfy schemas that require it =======
router.post('/add-balance', asyncHandler(async (req, res) => {
    const { username, amount } = req.body;

    // Basic validation and normalization
    if (!username) return res.status(400).json({ success: false, message: 'username is required' });
    if (typeof amount === 'undefined') return res.status(400).json({ success: false, message: 'amount is required' });

    const numAmount = Number(amount);
    if (isNaN(numAmount)) return res.status(400).json({ success: false, message: 'amount must be a number' });

    // Increment user's balance and return the updated document
    const user = await User.findOneAndUpdate({ username }, { $inc: { balance: numAmount } }, { new: true }).lean();
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    // Create a transaction record. Many schemas require userId — include it to avoid validation errors.
    const newTransaction = {
        user: username,
        userId: user._id, // <-- ensure required field is present
        type: "admin_add_balance",
        amount: numAmount,
        status: "Completed",
        createdAt: new Date().toISOString()
    };

    await Transaction.create(newTransaction);

    // Return success and updated balance for client convenience
    res.json({ success: true, balance: user.balance, user });
}));

router.post('/reset-user', asyncHandler(async (req, res) => {
    const { username } = req.body;
    const user = await User.findOne({ username }).lean();
    if (!user) return res.status(404).json({ success: false });
    await User.updateOne({ username }, {
        $set: {
            balance: 0,
            commission: 0,
            commissionToday: 0,
            status: "Active"
        }
    });
    res.json({ success: true });
}));
router.post('/assign-combo', asyncHandler(async (req, res) => {
    const { username, triggerTaskNumber, products } = req.body;
    const user = await User.findOne({ username }).lean();
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    await Combo.create({
        username,
        triggerTaskNumber,
        products
    });

    await Log.create({
        action: 'Combo Assigned (Manual)',
        username,
        combo: { triggerTaskNumber, products },
        timestamp: new Date().toISOString()
    });

    res.json({ success: true, message: 'Combo assigned successfully' });
}));
router.get('/export-logs-csv', asyncHandler(async (_, res) => {
    const logs = await Log.find({}).lean();
    if (!logs.length) return res.status(404).send('No logs found');
    const headers = Object.keys(logs[0]).join(',');
    const csv = [headers, ...logs.map(log => Object.values(log).map(v => `"${v}"`).join(','))].join('\n');
    res.setHeader('Content-Disposition', 'attachment; filename=logs.csv');
    res.setHeader('Content-Type', 'text/csv');
    res.send(csv);
}));

module.exports = router;

// server/models/LoginEvent.js
// Mongoose model for login/register events.

const mongoose = require('mongoose');

const LoginEventSchema = new mongoose.Schema({
  userId: { type: String, index: true, default: null },
  ip: { type: String, default: null },
  country: { type: String, default: null },
  region: { type: String, default: null },
  city: { type: String, default: null },
  latitude: { type: Number, default: null },
  longitude: { type: Number, default: null },
  userAgent: { type: String, default: null },
  action: { type: String, enum: ['login', 'register', 'other'], default: 'other' },
  createdAt: { type: String, default: () => new Date().toISOString() }
}, { collection: 'login_events', strict: false });

module.exports = mongoose.models.LoginEvent || mongoose.model('LoginEvent', LoginEventSchema);

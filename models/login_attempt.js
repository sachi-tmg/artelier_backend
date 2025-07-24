// models/LoginAttempt.js
const mongoose = require('mongoose');

const loginAttemptSchema = new mongoose.Schema({
  email: { type: String, required: true },
  ip: { type: String, required: true },
  successful: { type: Boolean, required: true },
  userAgent: String,
  createdAt: { type: Date, default: Date.now, expires: '24h' } // Auto-delete after 24h
});

module.exports = mongoose.model('LoginAttempt', loginAttemptSchema);
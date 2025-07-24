const mongoose = require("mongoose");

const loginAttemptSchema = new mongoose.Schema({
  ip: String,
  email: String,
  successful: Boolean,
  createdAt: {
    type: Date,
    default: Date.now,
    expires: 60 * 60 // Auto-delete after 1 hour
  }
});

module.exports = mongoose.model("LoginAttempt", loginAttemptSchema);

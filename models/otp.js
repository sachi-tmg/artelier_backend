const { default: mongoose } = require("mongoose");

// Create a model for OTPs
const otpSchema = new mongoose.Schema({
  email: { type: String, required: true, index: true },
  otp: { type: String, required: true },
  expiresAt: { type: Date, required: true, index: { expires: '15m' } }, // auto-delete after 15 mins
  createdAt: { type: Date, default: Date.now }
});

const Otp = mongoose.model("Otp", otpSchema);
module.exports = Otp;
const express = require("express");
const rateLimit = require("express-rate-limit");
const adminAuth = require('../middleware/admin_auth');
const userController = require("../controllers/user_controller");
const {
    verifyJWT,
} = require("../controllers/creation_controller");
const uploadsProf = require("../middleware/upload_profile.js");
const uploadsCov = require("../middleware/upload_cover.js");
const { trackLoginResult, trackRegistrationResult, trackPasswordResetResult } = require("../middleware/response_tracker");
const { checkPasswordExpiry } = require('../middleware/password_security');
const router = express.Router();

// Enhanced Rate Limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login requests per window
  message: {
    success: false,
    message: "Too many login attempts, please try again later"
  },
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      message: "Too many login attempts, please try again later"
    });
  }
});

const registrationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 registration attempts per hour per IP
  message: {
    success: false,
    message: "Too many registration attempts, please try again later"
  }
});

const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 password reset attempts per hour
  message: {
    success: false,
    message: "Too many password reset attempts, please try again later"
  }
});

const mfaLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 MFA attempts per 15 minutes
  message: {
    success: false,
    message: "Too many MFA attempts, please try again later"
  }
});

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3 // More strict limits for password reset
});

// Routes - removed all CAPTCHA middleware references
router.post("/registerUser", registrationLimiter, trackRegistrationResult(userController.register));
router.post("/login", loginLimiter, trackLoginResult(userController.login));
router.post("/verify-mfa", mfaLimiter, userController.verifyMfa);
router.post("/check-password-strength", userController.checkPasswordStrength);
router.post("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
  });
  return res.status(200).json({ success: true, message: "Logged out successfully" });
});

router.post("/profile", userController.findProfile);
router.post("/toggle-follow", verifyJWT, userController.toggleFollow);
router.post("/check-follow", verifyJWT, userController.checkFollowStatus);
router.get("/me", verifyJWT, userController.getCurrentUser);
router.put("/update-profile", verifyJWT, userController.updateProfile);
router.put("/update-password", verifyJWT, userController.updatePassword);
router.get("/password-status", verifyJWT, userController.checkPasswordStatus);
router.post("/admin/force-password-change", verifyJWT, adminAuth, userController.forcePasswordChange);
router.put("/update-notifications", verifyJWT, userController.updateNotifications);
router.post("/upload-profile-picture", verifyJWT, uploadsProf, userController.uploadProfile);
router.post("/upload-cover-picture", verifyJWT, uploadsCov, userController.uploadCover);
router.delete("/delete-account", verifyJWT, userController.deleteAccount);
router.post('/search-users', userController.searchUsers);
router.post('/auth/forgot-password', passwordResetLimiter, trackPasswordResetResult(userController.sendPasswordResetEmail));
router.post('/auth/reset-password', passwordResetLimiter, trackPasswordResetResult(userController.resetPassword));
router.post("/send-signup-otp", userController.sendSignupOtp);
router.post("/verify-signup-otp", userController.verifySignupOtp);
router.get('/verify-email', userController.verifyEmail);
router.post('/setup/initial-admin', userController.createInitialAdmin);

router.use(verifyJWT, checkPasswordExpiry);

// Admin-only risk assessment stats - need to import getRiskStats
// router.get('/admin/risk-stats', adminAuth, getRiskStats);

module.exports = router;
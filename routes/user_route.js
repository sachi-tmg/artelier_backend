const express = require("express");
const rateLimit = require("express-rate-limit");
const { adminAuth } = require('../middleware/admin_auth');
// const { 
//     register,
//     login,
//     findProfile,
//     toggleFollow,
//     checkFollowStatus,
//     getCurrentUser,
//   updateProfile,
//   updatePassword,
//   updateNotifications,
//   deleteAccount,
//   searchUsers,
//   uploadProfile,
//   uploadCover,
//   sendPasswordResetEmail,
//   resetPassword,
//   sendSignupOtp,
//   verifySignupOtp,
//   verifyEmail,
//   createAdminUser,
//   listAllUsers,
//   unlockUserAccount,
//   verifyMfa,
//   createAdmin,
// } = require("../controllers/user_controller");
const userController = require("../controllers/user_controller");
const {
    verifyJWT,
} = require("../controllers/creation_controller");
const uploadsProf = require("../middleware/upload_profile.js");
const uploadsCov = require("../middleware/upload_cover.js");
const router = express.Router();


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

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3 // More strict limits for password reset
});

router.post("/registerUser", userController.register);
router.post("/login", loginLimiter, userController.login);
router.post("/verify-mfa", userController.verifyMfa);
router.post("/profile", userController.findProfile);
router.post("/toggle-follow", verifyJWT, userController.toggleFollow);
router.post("/check-follow", verifyJWT, userController.checkFollowStatus);
router.get("/me", verifyJWT, userController.getCurrentUser);
router.put("/update-profile", verifyJWT, userController.updateProfile);
router.put("/update-password", verifyJWT, userController.updatePassword);
router.put("/update-notifications", verifyJWT, userController.updateNotifications);
router.post("/upload-profile-picture", verifyJWT, uploadsProf, userController.uploadProfile);
router.post("/upload-cover-picture", verifyJWT, uploadsCov, userController.uploadCover);
router.delete("/delete-account", verifyJWT, userController.deleteAccount);
router.post('/search-users', userController.searchUsers);
router.post('/auth/forgot-password', authLimiter, userController.sendPasswordResetEmail);
router.post('/auth/reset-password', authLimiter, userController.resetPassword);
router.post("/send-signup-otp", userController.sendSignupOtp);
router.post("/verify-signup-otp", userController.verifySignupOtp);
router.get('/verify-email', userController.verifyEmail);
router.post('/setup/initial-admin', userController.createInitialAdmin);

module.exports = router;
const express = require("express");
const { 
    register,
    login,
    findProfile,
    toggleFollow,
    checkFollowStatus,
    getCurrentUser,
  updateProfile,
  updatePassword,
  updateNotifications,
  deleteAccount,
  searchUsers,
  uploadProfile,
  uploadCover,
  sendPasswordResetEmail,
  resetPassword,
  sendOtp,
  verifyOtp,
  // resendOtp
} = require("../controllers/user_controller");
const {
    verifyJWT,
} = require("../controllers/creation_controller");
const uploadsProf = require("../middleware/upload_profile.js");
const uploadsCov = require("../middleware/upload_cover.js");
const router = express.Router();


router.post('/auth/otp-debug', (req, res) => {
  console.log('[DEBUG][otp-debug] Got body:', req.body);
  res.json({ ok: true });
});

router.post("/registerUser", register);
router.post("/login", login);
router.post("/profile", findProfile);
router.post("/toggle-follow", verifyJWT, toggleFollow);
router.post("/check-follow", verifyJWT, checkFollowStatus);
router.get("/me", verifyJWT, getCurrentUser);
router.put("/update-profile", verifyJWT, updateProfile);
router.put("/update-password", verifyJWT, updatePassword);
router.put("/update-notifications", verifyJWT, updateNotifications);
router.post("/upload-profile-picture", verifyJWT, uploadsProf, uploadProfile);
router.post("/upload-cover-picture", verifyJWT, uploadsCov, uploadCover);
router.delete("/delete-account", verifyJWT, deleteAccount);
router.post('/search-users', searchUsers); 
router.post('/auth/forgot-password', sendPasswordResetEmail);
router.post('/auth/reset-password', resetPassword);
router.post('/auth/send-otp', sendOtp);
router.post('/verify-otp', verifyOtp);
// router.post('/resend-otp', resendOtp);

module.exports = router;
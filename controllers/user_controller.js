const User = require("../models/user");
const LoginAttempt = require("../models/login_attempt");
const bcrypt = require("bcrypt");
require("dotenv").config();
const jwt = require("jsonwebtoken")
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const { validatePassword } = require('../utils/password_validator');
const AuditLogger = require('../services/audit_logger');
const pendingSignups = {};
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const register = async (req, res) => {
  try {
    const { fullName, email, password } = req.body;

    // Basic validation
    if (!fullName || fullName.trim().length < 2)
      return res.status(400).json({ message: "Full name too short." });

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ message: "Invalid email address." });

    if (!password) {
      return res.status(400).json({ message: "Password is required." });
    }

    // Enhanced password validation
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      return res.status(400).json({ 
        message: "Password does not meet security requirements.",
        errors: passwordValidation.errors,
        strength: passwordValidation.strength
      });
    }

    // Check existing user
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "Email already registered." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const username = await generateUsername(email);
    const verificationToken = crypto.randomBytes(20).toString("hex");
    const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);

    const newUser = new User({
      fullName,
      email,
      password: hashedPassword,
      username,
      emailVerificationToken: verificationToken,
      emailVerificationExpires: verificationExpires,
      isVerified: false,
      role: 'user' 
    });

    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}&email=${encodeURIComponent(email)}`;

    try {
      await sendVerificationEmail(email, verificationUrl); // ✉️ Send first
    } catch (emailError) {
      console.error("❌ Email failed to send:", emailError.message);
      return res.status(500).json({
        message: "Failed to send verification email. Please try again later."
      });
    }

    await newUser.save(); // ✅ Save only after email sent

    // Audit log account creation
    await AuditLogger.logAccountCreation(
      { _id: newUser._id, username: newUser.username, role: newUser.role },
      req.ip || req.connection.remoteAddress,
      req.headers['user-agent'],
      true
    );

    return res.status(201).json({
      success: true,
      message: "Verification email sent. Please check your inbox to complete registration."
    });

  } catch (err) {
    console.error("🚨 Registration Error:", err.message);
    
    // Audit log failed registration
    await AuditLogger.logAccountCreation(
      null,
      req.ip || req.connection.remoteAddress,
      req.headers['user-agent'],
      false,
      err.message
    );

    return res.status(500).json({
      message: "Server error during registration.",
      error: err.message
    });
  }
};

const generateUsername = async (email) => {
    let username = email.split("@")[0];

    let isUsernameNotUnique = await User.exists({username: username}).then((result) => result)

    isUsernameNotUnique ? username += uuidv4() : "";

    return username;
}

const sendVerificationEmail = async (email, verificationUrl) => {
  try {
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: process.env.EMAIL_SECURE === 'true',
      auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

    const mailOptions = {
      from: `"Artelier" <${process.env.EMAIL_FROM}>`,
      to: email,
      subject: "Verify Your Artelier Account",
      html: `
        <div style="font-family: Arial, sans-serif;">
          <h2>Please verify your email</h2>
          <p>Click below to complete your registration:</p>
          <a href="${verificationUrl}" style="...">Verify Email</a>
          <p>Or copy this link: ${verificationUrl}</p>
        </div>
      `
    };

    const info = await transporter.sendMail(mailOptions);
    console.log(`Verification email sent to ${email}:`, info.messageId);
    return true;
  } catch (err) {
    console.error("Failed to send verification email:", err);
    throw new Error("Failed to send verification email");
  }
};

const verifyEmail = async (req, res) => {
  try {
    const { token, email } = req.query;

    // 1. Check if required fields exist
    if (!token || !email) {
      return res.status(400).json({ 
        success: false,
        message: "Verification token and email are required" 
      });
    }

    // 2. Find user by email (regardless of token)
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: "User not found" 
      });
    }

    // 3. Check if already verified
    if (user.isVerified) {
      return res.status(200).json({ 
        success: true,
        message: "Email already verified. You can login." 
      });
    }

    // 4. Verify token only if not already verified
    if (user.emailVerificationToken !== token) {
      return res.status(400).json({ 
        success: false,
        message: "Invalid verification token" 
      });
    }

    if (user.emailVerificationExpires < Date.now()) {
      return res.status(400).json({ 
        success: false,
        message: "Verification link has expired" 
      });
    }

    // 5. Mark as verified
    user.isVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save();

    return res.status(200).json({ 
      success: true,
      message: "Email verified successfully. You can now login."
    });

  } catch (err) {
    console.error("Email verification error:", err);
    return res.status(500).json({ 
      success: false,
      message: "Failed to verify email" 
    });
  }
};


const resendVerificationEmail = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ success: false, message: "User not found" });
    if (user.isVerified) return res.status(400).json({ success: false, message: "Email already verified" });

    // regenerate token
    const token = crypto.randomBytes(20).toString("hex");
    user.emailVerificationToken = token;
    user.emailVerificationExpires = Date.now() + 3600000;
    await user.save();

    await sendVerificationEmail(user.email, token);
    return res.status(200).json({ success: true, message: "Verification email resent" });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Error resending email" });
  }
};

// user_controller.js
const login = async (req, res) => {
  const MAX_ATTEMPTS = 5;
  const LOCKOUT_TIME = 15 * 60 * 1000;
  const IP_ATTEMPT_WINDOW = 60 * 60 * 1000;
  const IP_MAX_ATTEMPTS = 20;

  try {
    const { email, password } = req.body;
    const ip = req.ip || req.connection.remoteAddress;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: "Email and password are required" });
    }

    // IP RATE LIMIT BLOCK
    const ipAttempts = await LoginAttempt.countDocuments({
      ip,
      createdAt: { $gt: new Date(Date.now() - IP_ATTEMPT_WINDOW) }
    });

    if (ipAttempts >= IP_MAX_ATTEMPTS) {
      return res.status(429).json({
        success: false,
        message: "Too many login attempts from your network. Try again later."
      });
    }

    // Find user
    const user = await User.findOne({ email }).select('+password +loginAttempts +loginLockUntil +isBanned');

    if (!user) {
      await LoginAttempt.create({ email, ip, successful: false });
      // Audit log failed login attempt
      await AuditLogger.logLogin(null, ip, req.headers['user-agent'], false, "Invalid email or password");
      return res.status(401).json({ success: false, message: "Invalid email or password" });
    }

    if (user.isBanned) {
      // Audit log banned user attempt
      await AuditLogger.logSuspiciousActivity(
        { _id: user._id, username: user.username, role: user.role },
        'banned_user_login_attempt',
        ip,
        req.headers['user-agent'],
        { resource: '/api/user/login', method: 'POST' }
      );
      return res.status(403).json({
        success: false,
        message: "Your account has been permanently banned due to repeated failed login attempts."
      });
    }

    if (user.loginLockUntil && user.loginLockUntil > Date.now()) {
      const remainingMinutes = Math.ceil((user.loginLockUntil - Date.now()) / 60000);
      return res.status(403).json({
        success: false,
        message: `Account temporarily locked. Try again in ${remainingMinutes} minute(s).`
      });
    }

    // Validate password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      await LoginAttempt.create({ email, ip, successful: false });

      const newAttempts = (user.loginAttempts || 0) + 1;
      let updateFields = { loginAttempts: newAttempts };

      if (newAttempts >= MAX_ATTEMPTS) {
        updateFields.loginLockUntil = Date.now() + LOCKOUT_TIME;
        updateFields.isBanned = true; // Permanent ban
        
        // Audit log account lockout
        await AuditLogger.log({
          action: 'account_locked',
          resource: '/api/user/login',
          method: 'POST',
          status: 'warning',
          user: { _id: user._id, username: user.username, role: user.role },
          ipAddress: ip,
          userAgent: req.headers['user-agent'],
          details: { attempts: newAttempts, lockoutTime: LOCKOUT_TIME }
        });
      }

      await User.updateOne({ email }, updateFields);
      
      // Audit log failed login
      await AuditLogger.logLogin(
        { _id: user._id, username: user.username, role: user.role },
        ip,
        req.headers['user-agent'],
        false,
        "Invalid email or password"
      );

      return res.status(401).json({ success: false, message: "Invalid email or password" });
    }

    // Account verified check
    if (!user.isVerified) {
      return res.status(403).json({ success: false, message: "Please verify your email before logging in." });
    }

    // ✅ LOGIN SUCCESSFUL — reset counters
    await User.updateOne({ email }, { $set: { loginAttempts: 0, loginLockUntil: null } });
    await LoginAttempt.create({ email, ip, successful: true });

    // Audit log successful login (partial - MFA still required)
    await AuditLogger.log({
      action: 'login_attempt',
      resource: '/api/user/login',
      method: 'POST',
      status: 'info',
      user: { _id: user._id, username: user.username, role: user.role },
      ipAddress: ip,
      userAgent: req.headers['user-agent'],
      details: { stage: 'password_verified', mfaRequired: true }
    });

    // MFA OTP generation
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 mins

    user.mfaOtp = otp;
    user.mfaOtpExpires = otpExpires;
    await user.save();

    await sendOtpEmail(user.email, otp, "login");

    const tempToken = jwt.sign(
      {
        userId: user._id,
        mfa: true
      },
      process.env.SECRET_KEY,
      { expiresIn: "15m" }
    );

    return res.status(200).json({
      mfaRequired: true,
      tempToken,
      message: "OTP sent to your email. Please verify."
    });

  } catch (err) {
    console.error("Login error:", err);
    
    // Audit log login error
    await AuditLogger.log({
      action: 'login_failure',
      resource: '/api/user/login',
      method: 'POST',
      status: 'failure',
      user: null,
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.headers['user-agent'],
      errorMessage: err.message
    });

    return res.status(500).json({ success: false, message: "An error occurred during login" });
  }
};




const verifyMfa = async (req, res) => {
  const { tempToken, code } = req.body;

  if (!tempToken || !code) {
    return res.status(400).json({ message: "Missing temp token or verification code" });
  }

  try {
    const decoded = jwt.verify(tempToken, process.env.SECRET_KEY);
    const user = await User.findById(decoded.userId);

    if (!user || !user.mfaOtp) {
      return res.status(403).json({ message: "OTP not found or user invalid" });
    }

    const isCodeMatch = user.mfaOtp === code;
    const isExpired = Date.now() > user.mfaOtpExpires;


    if (!isCodeMatch || isExpired) {
      // Audit log failed MFA attempt
      await AuditLogger.logMfaAttempt(
        { _id: user._id, username: user.username, role: user.role },
        req.ip || req.connection.remoteAddress,
        req.headers['user-agent'],
        false,
        "Invalid or expired MFA code"
      );
      return res.status(403).json({ message: "Invalid or expired MFA code" });
    }

    // Clear OTP after successful use and update lastActive
    user.mfaOtp = undefined;
    user.mfaOtpExpires = undefined;
    user.lastActive = new Date();

    await user.save();

    // Audit log successful MFA and complete login
    await AuditLogger.logMfaAttempt(
      { _id: user._id, username: user.username, role: user.role },
      req.ip || req.connection.remoteAddress,
      req.headers['user-agent'],
      true
    );

    await AuditLogger.logLogin(
      { _id: user._id, username: user.username, role: user.role },
      req.ip || req.connection.remoteAddress,
      req.headers['user-agent'],
      true
    );

    const finalToken = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.SECRET_KEY,
      { expiresIn: "1d" }
    );

    res.cookie("token", finalToken, {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      maxAge: 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      success: true,
      message: "MFA verification successful",
      user: {
        _id: user._id,
        username: user.username,
        role: user.role,
        profilePicture: user.profilePicture,
        coverPicture: user.coverPicture
      }
    });
  } catch (err) {
    console.error("verifyMfa error:", err);
    
    // Audit log MFA error
    await AuditLogger.log({
      action: 'mfa_failure',
      resource: '/api/user/verify-mfa',
      method: 'POST',
      status: 'failure',
      user: null,
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.headers['user-agent'],
      errorMessage: err.message
    });

    return res.status(500).json({ message: "Internal server error" });
  }
};


const findProfile = async (req, res) => {
    try {
        let { username } = req.body; // Assuming username comes from body, could also be params

        // Find the user by username
        const user = await User.findOne({ username })
            .select("-password -google_auth -roleId -loggedInOnce") // Exclude sensitive fields
            // Populate followers and following counts without bringing all data
            .populate({
                path: 'followers',
                select: '_id', // Just select ID to count
            })
            .populate({
                path: 'following',
                select: '_id', // Just select ID to count
            });

        if (!user) {
            return res.status(404).json({ message: "User profile not found." });
        }

        // Convert Mongoose document to a plain object
        const userObject = user.toObject();

        // Add follower and following counts directly
        userObject.followerCount = userObject.followers ? userObject.followers.length : 0;
        userObject.followingCount = userObject.following ? userObject.following.length : 0;

        // Remove the large arrays from the final response if only counts are needed
        delete userObject.followers;
        delete userObject.following;

        // In your original findProfile, you had regularUser schema.
        // If 'bio', 'profilePicture', 'link', 'account_info' are directly on the User model
        // (as per your provided userSchema), then the 'regularUser' sub-object might not be needed.
        // I'm assuming for the follow controller that these are directly on the User model.
        // If you *still* use a separate RegularUser model, you'd need to adjust accordingly.

        return res.status(200).json({
            user: userObject
        });

    } catch (e) {
        console.error("Error fetching profile:", e);
        res.status(500).json({ message: "Server error", error: e.message });
    }
};

// Admin-only functions
const createAdminUser = async (req, res) => {
  try {
    const { fullName, email, password } = req.body;

    // Basic validation
    if (!fullName || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Check existing user
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "Email already registered." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const username = await generateUsername(email);

    const newAdmin = new User({
      fullName,
      email,
      password: hashedPassword,
      username,
      role: 'admin',
      isVerified: true // Admins don't need email verification
    });

    await newAdmin.save();

    return res.status(201).json({
      success: true,
      message: "Admin user created successfully"
    });

  } catch (err) {
    console.error("Admin creation error:", err);
    return res.status(500).json({
      message: "Server error during admin creation",
      error: err.message
    });
  }
};

const listAllUsers = async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '' } = req.query;
    
    const query = {};
    if (search) {
      query.$or = [
        { fullName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { username: { $regex: search, $options: 'i' } }
      ];
    }

    const users = await User.find(query)
      .select('-password -mfaSecret -backupCodes') // Exclude sensitive info
      .skip((page - 1) * limit)
      .limit(limit)
      .sort({ createdAt: -1 });

    const totalUsers = await User.countDocuments(query);

    return res.status(200).json({
      success: true,
      users,
      total: totalUsers,
      page: parseInt(page),
      pages: Math.ceil(totalUsers / limit)
    });

  } catch (err) {
    console.error("Error listing users:", err);
    return res.status(500).json({
      message: "Server error while fetching users",
      error: err.message
    });
  }
};

const unlockUserAccount = async (req, res) => {
  try {
    const { userId } = req.body;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID" });
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { 
        loginAttempts: 0,
        loginLockUntil: null 
      },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({
      success: true,
      message: "User account unlocked successfully"
    });

  } catch (err) {
    console.error("Error unlocking account:", err);
    return res.status(500).json({
      message: "Server error while unlocking account",
      error: err.message
    });
  }
};


const toggleFollow = async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        const { targetUserId } = req.body; // The ID of the user to follow/unfollow
        const followerId = req.user.userId; // The ID of the authenticated user (from JWT payload)

        if (!followerId) {
            await session.abortTransaction();
            session.endSession();
            return res.status(401).json({ message: "Authentication required to perform this action." });
        }

        if (followerId === targetUserId) {
            await session.abortTransaction();
            session.endSession();
            return res.status(400).json({ message: "You cannot follow yourself." });
        }

        const [follower, targetUser] = await Promise.all([
            User.findById(followerId).session(session),
            User.findById(targetUserId).session(session)
        ]);

        if (!follower) {
            await session.abortTransaction();
            session.endSession();
            return res.status(404).json({ message: "Follower user not found." });
        }
        if (!targetUser) {
            await session.abortTransaction();
            session.endSession();
            return res.status(404).json({ message: "Target user not found." });
        }

        let message = "";
        let isNowFollowing;

        // Check if the follower is already following the targetUser
        const isFollowing = follower.following.includes(targetUserId);

        if (isFollowing) {
            // Unfollow logic
            await User.findByIdAndUpdate(
                followerId,
                { $pull: { following: targetUserId } },
                { new: true, session: session }
            );

            await User.findByIdAndUpdate(
                targetUserId,
                { $pull: { followers: followerId } },
                { new: true, session: session }
            );
            message = "Unfollowed successfully.";
            isNowFollowing = false;
        } else {
            // Follow logic
            await User.findByIdAndUpdate(
                followerId,
                { $push: { following: targetUserId } },
                { new: true, session: session }
            );

            await User.findByIdAndUpdate(
                targetUserId,
                { $push: { followers: followerId } },
                { new: true, session: session }
            );
            message = "Followed successfully.";
            isNowFollowing = true;
        }

        await session.commitTransaction();
        session.endSession();

        // Optionally, fetch updated counts for the target user to send back
        const updatedTargetUser = await User.findById(targetUserId).select('followers following');
        const updatedFollowerCount = updatedTargetUser.followers.length;


        return res.status(200).json({
            success: true,
            message,
            isNowFollowing,
            updatedFollowerCount, // Send back the updated count
        });

    } catch (e) {
        await session.abortTransaction();
        session.endSession();
        console.error("Error in toggleFollow:", e);
        res.status(500).json({ message: "Server error during follow/unfollow operation.", error: e.message });
    }
};


const checkFollowStatus = async (req, res) => {
    try {
        const { targetUserId } = req.body;
        const followerId = req.user.userId;

        if (!followerId) {
            return res.status(401).json({ message: "Authentication required." });
        }

        const follower = await User.findById(followerId);
        if (!follower) {
            return res.status(404).json({ message: "User not found." });
        }

        const isFollowing = follower.following.includes(targetUserId);
        
        return res.status(200).json({
            isFollowing
        });

    } catch (e) {
        console.error("Error checking follow status:", e);
        res.status(500).json({ message: "Server error", error: e.message });
    }
};

const getCurrentUser = async (req, res) => {
    try {
        const userId = req.user.userId;
        
        const user = await User.findById(userId)
            .select("-password -google_auth -roleId");

        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }

        return res.status(200).json({
            user
        });

    } catch (e) {
        console.error("Error fetching current user:", e);
        res.status(500).json({ message: "Server error", error: e.message });
    }
};


// Add to user_controller.js
const updateProfile = async (req, res) => {
    try {
        const { fullName, bio, username, profilePicture, coverPicture, website } = req.body;
        const userId = req.user.userId;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        const updateFields = {};

        // Conditionally add fields to updateFields if they are provided in the request
        if (fullName !== undefined) updateFields.fullName = fullName;
        if (bio !== undefined) updateFields.bio = bio;
        // profilePicture is expected to be a URL string here.
        // If you are uploading a file, that should happen via a separate endpoint
        // which returns a URL, and then this URL is sent to this updateProfile.
        if (profilePicture !== undefined) updateFields.profilePicture = profilePicture;
        if (coverPicture !== undefined) updateFields.coverPicture = coverPicture;

        // Map frontend's 'website' to backend's 'link'
        if (website !== undefined) updateFields.link = website;

        // Handle username update separately due to uniqueness constraint
        if (username !== undefined && username !== user.username) {
            const existingUserWithNewUsername = await User.findOne({ username });
            if (existingUserWithNewUsername && existingUserWithNewUsername._id.toString() !== userId) {
                return res.status(409).json({ message: "This username is already taken. Please choose another." });
            }
            updateFields.username = username;
        }

        // Perform the update
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            updateFields,
            { new: true, runValidators: true } // 'new: true' returns the updated document; 'runValidators: true' applies schema validators
        ).select("-password"); // Exclude sensitive fields from the response

        // Audit log profile update
        await AuditLogger.logProfileUpdate(
            { _id: userId, username: updatedUser.username, role: updatedUser.role },
            req.ip || req.connection.remoteAddress,
            req.headers['user-agent'],
            Object.keys(updateFields)
        );

        res.status(200).json({
            success: true,
            message: "Profile updated successfully!",
            user: updatedUser
        });
    } catch (error) {
        console.error("Error updating profile:", error);
        
        // Audit log failed profile update
        await AuditLogger.logProfileUpdate(
            { _id: userId, username: req.user.username, role: req.user.role },
            req.ip || req.connection.remoteAddress,
            req.headers['user-agent'],
            [],
            false
        );

        // Handle Mongoose validation errors (e.g., if a field doesn't meet schema requirements)
        if (error.name === 'ValidationError') {
            return res.status(400).json({ message: error.message, error: error.errors });
        }
        // Handle duplicate key error specifically for username
        if (error.code === 11000 && error.keyPattern && error.keyPattern.username) {
            return res.status(409).json({ message: "This username is already taken. Please choose another.", error: error.message });
        }
        res.status(500).json({ message: "Error updating profile", error: error.message });
    }
};


const updatePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.userId;

    // Basic validation
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: "Current password and new password are required" });
    }

    // Enhanced password validation for new password
    const passwordValidation = validatePassword(newPassword);
    if (!passwordValidation.isValid) {
      return res.status(400).json({ 
        message: "New password does not meet security requirements.",
        errors: passwordValidation.errors,
        strength: passwordValidation.strength
      });
    }

    const user = await User.findById(userId).select('+password');
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Current password is incorrect" });
    }

    // Check if new password is the same as current password
    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      return res.status(400).json({ message: "New password must be different from current password" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    // Audit log password change
    await AuditLogger.logPasswordChange(
      { _id: user._id, username: user.username, role: user.role },
      req.ip || req.connection.remoteAddress,
      req.headers['user-agent'],
      true
    );

    res.status(200).json({ 
      success: true, 
      message: "Password updated successfully",
      passwordStrength: passwordValidation.strength
    });
  } catch (error) {
    // Audit log failed password change
    await AuditLogger.logPasswordChange(
      { _id: req.user.userId, username: req.user.username, role: req.user.role },
      req.ip || req.connection.remoteAddress,
      req.headers['user-agent'],
      false,
      error.message
    );

    res.status(500).json({ message: "Error updating password", error: error.message });
  }
};

const updateNotifications = async (req, res) => {
  try {
    const { comments, likes, messages } = req.body;
    const userId = req.user.userId;

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { 
        notifications: { comments, likes, messages } 
      },
      { new: true }
    ).select("-password");

    res.status(200).json({ 
      success: true,
      message: "Notification preferences updated"
    });
  } catch (error) {
    res.status(500).json({ message: "Error updating notifications", error: error.message });
  }
};

const uploadProfile = async (req, res) => {
    // Ensure you have access to userId from the JWT payload
    const userId = req.user.userId; 

    if (!req.file) {
        return res.status(400).json({ 
            success: false,
            message: "Please select an image file to upload",
            code: 'NO_FILE_SELECTED'
        });
    }

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const imageUrl = `${baseUrl}/public/Profiles/${req.file.filename}`; 

    try {
        // Find the user and update their profilePicture field
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { profilePicture: imageUrl },
            { new: true, runValidators: true } // Return the updated user and run schema validators
        ).select("-password"); // Exclude sensitive info from the response

        if (!updatedUser) {
            return res.status(404).json({ 
                success: false,
                message: "User not found",
                code: 'USER_NOT_FOUND'
            });
        }

        res.status(200).json({
            success: true,
            message: "Profile picture uploaded successfully!",
            profilePictureUrl: updatedUser.profilePicture, // Send back the updated URL
            user: {
                userId: updatedUser._id,
                email: updatedUser.email,
                username: updatedUser.username,
                fullName: updatedUser.fullName,
                profilePicture: updatedUser.profilePicture,
                coverPicture: updatedUser.coverPicture,
                bio: updatedUser.bio, // Include other relevant fields if needed
                link: updatedUser.link
            }
        });
    } catch (error) {
        console.error("Error uploading or updating profile picture:", error);
        // Handle specific errors like file system issues or database errors
        res.status(500).json({ 
            success: false,
            message: "Server error during profile picture upload", 
            code: 'SERVER_ERROR'
        });
    }
};

const uploadCover = async (req, res) => {
    // Ensure you have access to userId from the JWT payload
    const userId = req.user.userId; 

    if (!req.file) {
        return res.status(400).json({ 
            success: false,
            message: "Please select an image file to upload",
            code: 'NO_FILE_SELECTED'
        });
    }

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const imageUrl = `${baseUrl}/public/Covers/${req.file.filename}`; 

    try {
        // Find the user and update their profilePicture field
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { coverPicture: imageUrl },
            { new: true, runValidators: true } // Return the updated user and run schema validators
        ).select("-password"); // Exclude sensitive info from the response

        if (!updatedUser) {
            return res.status(404).json({ 
                success: false,
                message: "User not found",
                code: 'USER_NOT_FOUND'
            });
        }

        res.status(200).json({
            success: true,
            message: "Cover picture uploaded successfully!",
            coverPictureUrl: updatedUser.coverPicture, // Send back the updated URL
            user: {
                userId: updatedUser._id,
                email: updatedUser.email,
                username: updatedUser.username,
                fullName: updatedUser.fullName,
                profilePicture: updatedUser.profilePicture,
                coverPicture: updatedUser.coverPicture,
                bio: updatedUser.bio, // Include other relevant fields if needed
                link: updatedUser.link
            }
        });
    } catch (error) {
        console.error("Error uploading or updating cover picture:", error);
        // Handle specific errors like file system issues or database errors
        res.status(500).json({ 
            success: false,
            message: "Server error during cover picture upload", 
            code: 'SERVER_ERROR'
        });
    }
};

const deleteAccount = async (req, res) => {
  try {
    const userId = req.user.userId;
    await User.findByIdAndDelete(userId);
    res.status(200).json({ success: true, message: "Account deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting account", error: error.message });
  }
};

const searchUsers = async (req, res) => {
    let { query, page } = req.body;
    let maxLimit = 10; // Or whatever limit you want for user search

    let findQuery = {};
    if (query) {
        const searchRegex = new RegExp(query, 'i');
        findQuery.$or = [
            { username: searchRegex },
            { fullName: searchRegex },
        ];
    }

    try {
        const users = await User.find(findQuery)
            .select("fullName username profilePicture email") // Select relevant user fields
            .skip((page - 1) * maxLimit)
            .limit(maxLimit);

        // You might want to return totalDocs for users too if you plan to paginate them
        const totalDocs = await User.countDocuments(findQuery);

        return res.status(200).json({ users, totalDocs }); // Return users and totalDocs
    } catch (e) {
        console.error("Error searching users:", e);
        return res.status(500).json({ message: "Server error", error: e.message });
    }
};

// Helper function to generate reset token
const generateResetToken = () => {
  return crypto.randomBytes(20).toString('hex');
};

// Send password reset email
const sendPasswordResetEmail = async (req, res) => {
  try {
    const { email } = req.body;

    // Validate email
    if (!email || typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ message: "Please provide a valid email address." });
    }

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      // For security, don't reveal if email doesn't exist
      return res.status(200).json({ 
        success: true,
        message: "If an account with that email exists, a password reset link has been sent."
      });
    }

    // Generate reset token and set expiration (1 hour from now)
    const resetToken = generateResetToken();
    const resetExpires = new Date(Date.now() + 3600000); // 1 hour

    // Save token and expiration to user
    user.passwordResetToken = resetToken;
    user.passwordResetExpires = resetExpires;
    await user.save();

    // Create reset URL (matches your frontend route)
    const resetUrl = `${process.env.FRONTEND_URL || 'https://localhost:3000'}/forgot-password?token=${resetToken}&email=${encodeURIComponent(user.email)}`;

    // Create email transporter
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: process.env.EMAIL_SECURE === 'true',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    // Email options
    const mailOptions = {
      from: `"Your App Name" <${process.env.EMAIL_FROM || process.env.EMAIL_USER}>`,
      to: user.email,
      subject: 'Password Reset Request',
      html: `
        <p>You requested a password reset for your account.</p>
        <p>Click this link to reset your password:</p>
        <p><a href="${resetUrl}">${resetUrl}</a></p>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request this, please ignore this email.</p>
      `
    };

    // Send email
    await transporter.sendMail(mailOptions);

    res.status(200).json({ 
      success: true,
      message: "If an account with that email exists, a password reset link has been sent."
    });

  } catch (error) {
    console.error("Error sending password reset email:", error);
    res.status(500).json({ 
      message: "Error sending password reset email.", 
      error: error.message 
    });
  }
};

const resetPassword = async (req, res) => {
  try {
    const { token, email, newPassword } = req.body;
    const normalizedEmail = email.toLowerCase().trim();

    // Debug logging
    console.log('Reset password request:', { 
      email: normalizedEmail,
      token,
      time: new Date() 
    });

    // Validate inputs
    if (!token || !email || !newPassword) {
      return res.status(400).json({ message: "Token, email, and new password are required." });
    }

    // Enhanced password validation
    const passwordValidation = validatePassword(newPassword);
    if (!passwordValidation.isValid) {
      return res.status(400).json({ 
        message: "New password does not meet security requirements.",
        errors: passwordValidation.errors,
        strength: passwordValidation.strength
      });
    }

    // Find user
    const user = await User.findOne({ 
      email: normalizedEmail,
      passwordResetToken: token,
      passwordResetExpires: { $gt: Date.now() }
    }).select('+password');

    if (!user) {
      // More detailed error logging
      const existingUser = await User.findOne({ email: normalizedEmail });
      console.log('User exists:', !!existingUser);
      if (existingUser) {
        console.log('Token match:', existingUser.passwordResetToken === token);
        console.log('Token expiry:', existingUser.passwordResetExpires);
        console.log('Current time:', new Date());
      }
      
      return res.status(400).json({ 
        message: "Password reset token is invalid or has expired. Please request a new reset link." 
      });
    }

    // Check if new password is the same as current password
    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      return res.status(400).json({ message: "New password must be different from current password" });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user password and clear reset token
    user.password = hashedPassword;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    // Optionally send confirmation email
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: process.env.EMAIL_SECURE === 'true',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    const mailOptions = {
      from: `"Your App Name" <${process.env.EMAIL_FROM || process.env.EMAIL_USER}>`,
      to: user.email,
      subject: 'Password Changed Successfully',
      html: `
        <p>Your password has been successfully changed.</p>
        <p>If you didn't make this change, please contact us immediately.</p>
      `
    };

    try {
      await transporter.sendMail(mailOptions);
    } catch (emailError) {
      console.error("Error sending password change confirmation:", emailError);
      // Don't fail the request if email fails
    }

    res.status(200).json({ 
      success: true,
      message: "Password has been reset successfully. You can now login with your new password."
    });

  } catch (error) {
    console.error("Error resetting password:", error);
    res.status(500).json({ 
      message: "Error resetting password.", 
      error: error.message 
    });
  }
};

const generateOtp = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

const sendOtpEmail = async (email, otp, purpose = "login") => {
  try {
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: process.env.EMAIL_SECURE === 'true',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    // Customize based on purpose
    const title = "Your Verification Code";
    const actionText = purpose === "signup"
      ? "Use this code to complete your registration:"
      : "Use this code to verify your login:";

    const mailOptions = {
      from: `"Artelier" <${process.env.EMAIL_FROM}>`,
      to: email,
      subject: "Your Artelier Verification Code",
      html: `
        <div style="font-family: Arial, sans-serif;">
          <h2>${title}</h2>
          <p>${actionText}</p>
          <div style="font-size: 24px; font-weight: bold; margin: 20px 0;">${otp}</div>
          <p>This code will expire in 15 minutes.</p>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log(`OTP email sent to ${email} for ${purpose}`);
    return true;
  } catch (err) {
    console.error("Failed to send OTP email:", err);
    throw new Error("Failed to send OTP email");
  }
};



const sendSignupOtp = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ message: "Invalid email address" });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "Email already registered" });
    }

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    // Store in pendingSignups (in-memory for now - consider Redis in production)
    pendingSignups[email] = {
      otp,
      otpExpires,
      attempts: 0
    };

    // Send OTP email
    await sendOtpEmail(email, otp, "signup");

    res.status(200).json({
      success: true,
      message: "OTP sent to your email"
    });
  } catch (err) {
    console.error("OTP send error:", err);
    res.status(500).json({
      message: "Failed to send OTP",
      error: err.message
    });
  }
};

const verifySignupOtp = async (req, res) => {
  try {
    const { email, otp, fullName, password } = req.body;

    // Basic validation
    if (!email || !otp || !fullName || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Get pending OTP
    const pendingOtp = pendingSignups[email];
    if (!pendingOtp) {
      return res.status(400).json({ message: "No OTP request found for this email" });
    }

    // Check attempts
    if (pendingOtp.attempts >= 3) {
      delete pendingSignups[email];
      return res.status(400).json({ message: "Too many attempts. Please request a new OTP." });
    }

    // Check expiration
    if (pendingOtp.otpExpires < new Date()) {
      delete pendingSignups[email];
      return res.status(400).json({ message: "OTP expired. Please request a new one." });
    }

    // Verify OTP
    if (pendingOtp.otp !== otp) {
      pendingOtp.attempts += 1;
      return res.status(400).json({ message: "Invalid OTP" });
    }

    // OTP verified - create user
    const hashedPassword = await bcrypt.hash(password, 10);
    const username = await generateUsername(email);

    const newUser = new User({
      fullName,
      email,
      password: hashedPassword,
      username,
      isVerified: true // Since we verified via OTP
    });

    await newUser.save();
    delete pendingSignups[email];

    // Generate JWT token for immediate login
    const token = jwt.sign(
      {
        userId: newUser._id,
        email: newUser.email,
        username: newUser.username,
      },
      process.env.SECRET_KEY,
      { expiresIn: "90d" }
    );

    res.status(201).json({
      success: true,
      message: "Registration successful",
      token,
      user: {
        userId: newUser._id,
        email: newUser.email,
        username: newUser.username,
        fullName: newUser.fullName,
        profilePicture: newUser.profilePicture || null,
        coverPicture: newUser.coverPicture || null
      }
    });
  } catch (err) {
    console.error("OTP verification error:", err);
    res.status(500).json({
      message: "Registration failed",
      error: err.message
    });
  }
};

const createAdmin = async (req, res) => {
  try {
    const { email, password, fullName } = req.body;
    
    // Check if any admin exists
    const adminExists = await User.findOne({ role: 'admin' });
    if (adminExists) {
      return res.status(400).json({ message: "An admin already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const username = email.split('@')[0] + '-admin';

    const admin = new User({
      email,
      password: hashedPassword,
      fullName,
      username,
      role: 'admin',
      isVerified: true
    });

    await admin.save();

    return res.status(201).json({
      success: true,
      message: "First admin created successfully"
    });
  } catch (err) {
    console.error("Error creating first admin:", err);
    return res.status(500).json({
      message: "Error creating first admin",
      error: err.message
    });
  }
};

const createInitialAdmin = async (req, res) => {
  try {
    // Check if any admin exists
    const adminExists = await User.findOne({ role: 'admin' });
    if (adminExists) {
      return res.status(400).json({ 
        success: false,
        message: "Admin already exists. Only one admin can be created."
      });
    }

    const { email, password, fullName } = req.body;
    
    // Validate inputs
    if (!email || !password || !fullName) {
      return res.status(400).json({ 
        success: false,
        message: "Email, password and full name are required" 
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const username = email.split('@')[0] + '-admin';

    const admin = new User({
      email,
      password: hashedPassword,
      fullName,
      username,
      role: 'admin',
      isVerified: true
    });

    await admin.save();

    return res.status(201).json({
      success: true,
      message: "Initial admin created successfully"
    });
  } catch (err) {
    console.error("Error creating initial admin:", err);
    return res.status(500).json({
      success: false,
      message: "Error creating initial admin",
      error: err.message
    });
  }
};

// Password strength checker endpoint
const checkPasswordStrength = async (req, res) => {
  try {
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({ message: "Password is required" });
    }

    const passwordValidation = validatePassword(password);
    
    return res.status(200).json({
      success: true,
      validation: {
        isValid: passwordValidation.isValid,
        strength: passwordValidation.strength,
        errors: passwordValidation.errors,
        requirements: {
          minLength: password.length >= 8,
          hasLowercase: /[a-z]/.test(password),
          hasUppercase: /[A-Z]/.test(password),
          hasNumber: /\d/.test(password),
          hasSpecialChar: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
          isNotCommon: !['password', '123456', '12345678', 'qwerty', 'abc123', 'password123', 'admin', 'letmein', 'welcome', '123456789'].includes(password.toLowerCase())
        }
      }
    });

  } catch (error) {
    console.error("Error checking password strength:", error);
    return res.status(500).json({ 
      message: "Error checking password strength", 
      error: error.message 
    });
  }
};

// Add to exports
module.exports = {
  register,
  verifyMfa,
  login,
  findProfile,
  toggleFollow,
  checkFollowStatus,
  getCurrentUser,
  updateProfile,
  uploadProfile,
  uploadCover,
  updatePassword,
  updateNotifications,
  deleteAccount,
  searchUsers,
  sendPasswordResetEmail,
  resetPassword,
  sendSignupOtp,
  verifySignupOtp,
  verifyEmail,
  resendVerificationEmail,
  createAdminUser,
  listAllUsers,
  unlockUserAccount,
  createAdmin,
  createInitialAdmin,
  checkPasswordStrength
};



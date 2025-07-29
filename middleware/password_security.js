const User = require('../models/user');
const bcrypt = require('bcrypt');

// Check if password has expired
const checkPasswordExpiry = async (req, res, next) => {
  try {
    if (req.user) {
      const user = await User.findById(req.user.userId).select('+passwordExpiresAt +mustChangePassword');
      
      if (user.mustChangePassword || (user.passwordExpiresAt && new Date() > user.passwordExpiresAt)) {
        return res.status(401).json({
          success: false,
          message: "Password has expired. Please change your password.",
          passwordExpired: true
        });
      }
    }
    next();
  } catch (error) {
    console.error('Password expiry check error:', error);
    next();
  }
};

// Check password reuse (function to be used in controllers)
const checkPasswordReuse = async (userId, newPassword, historyLimit = 5) => {
  try {
    const user = await User.findById(userId).select('+passwordHistory +password');
    
    if (!user) {
      throw new Error('User not found');
    }

    // Check against current password
    const isSameAsCurrent = await bcrypt.compare(newPassword, user.password);
    if (isSameAsCurrent) {
      throw new Error('New password cannot be the same as current password');
    }

    // Check against password history
    if (user.passwordHistory && user.passwordHistory.length > 0) {
      const recentPasswords = user.passwordHistory
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
        .slice(0, historyLimit);

      for (const oldPassword of recentPasswords) {
        const isReused = await bcrypt.compare(newPassword, oldPassword.hash);
        if (isReused) {
          throw new Error(`Cannot reuse any of your last ${historyLimit} passwords`);
        }
      }
    }

    return true;
  } catch (error) {
    throw error;
  }
};

// Add password to history
const addPasswordToHistory = async (userId, hashedPassword) => {
  try {
    const user = await User.findById(userId);
    if (!user) return;

    // Initialize passwordHistory if it doesn't exist
    if (!user.passwordHistory) {
      user.passwordHistory = [];
    }

    // Add current password to history
    user.passwordHistory.push({
      hash: hashedPassword,
      createdAt: new Date()
    });

    // Keep only last 10 passwords in history
    if (user.passwordHistory.length > 10) {
      user.passwordHistory = user.passwordHistory.slice(-10);
    }

    // Update password expiry and reset change flag
    user.passwordExpiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000); // 90 days
    user.mustChangePassword = false;
    user.passwordLastChanged = new Date();

    await user.save();
  } catch (error) {
    console.error('Error adding password to history:', error);
  }
};

module.exports = {
  checkPasswordExpiry,
  checkPasswordReuse,
  addPasswordToHistory
};
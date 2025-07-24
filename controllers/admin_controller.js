// controllers/adminController.js

const User = require("../models/user");
const LoginAttempt = require("../models/login_attempt");
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");

// Enhanced listAllUsers with more filtering options
const listAllUsers = async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 20, 
      search = '',
      role = '',
      status = '',
      sortBy = 'createdAt',
      sortOrder = 'desc'
    } = req.query;
    
    const query = {};
    
    // Search filter
    if (search) {
      query.$or = [
        { fullName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { username: { $regex: search, $options: 'i' } }
      ];
    }
    
    // Role filter
    if (role) {
      query.role = role;
    }
    
    // Status filter
    if (status === 'active') {
      query.isVerified = true;
      query.isBanned = false;
    } else if (status === 'banned') {
      query.isBanned = true;
    } else if (status === 'unverified') {
      query.isVerified = false;
    } else if (status === 'locked') {
      query.loginLockUntil = { $gt: Date.now() };
    }

    const sort = {};
    sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

    const users = await User.find(query)
      .select('-password -mfaSecret -backupCodes') // Exclude sensitive info
      .skip((page - 1) * limit)
      .limit(limit)
      .sort(sort);

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

// Get single user details
const getUserDetails = async (req, res) => {
  try {
    const { userId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID" });
    }

    const user = await User.findById(userId)
      .select('-password -mfaSecret -backupCodes')
      .populate('followers following', 'username fullName profilePicture');

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({
      success: true,
      user
    });

  } catch (err) {
    console.error("Error getting user details:", err);
    return res.status(500).json({
      message: "Server error while fetching user details",
      error: err.message
    });
  }
};

// Update user role/status
const updateUser = async (req, res) => {
  try {
    const { userId } = req.params;
    const { role, isVerified, isBanned } = req.body;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID" });
    }

    const updates = {};
    if (role !== undefined) updates.role = role;
    if (isVerified !== undefined) updates.isVerified = isVerified;
    if (isBanned !== undefined) updates.isBanned = isBanned;

    const user = await User.findByIdAndUpdate(
      userId,
      updates,
      { new: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({
      success: true,
      message: "User updated successfully",
      user
    });

  } catch (err) {
    console.error("Error updating user:", err);
    return res.status(500).json({
      message: "Server error while updating user",
      error: err.message
    });
  }
};

// Delete user
const deleteUser = async (req, res) => {
  try {
    const { userId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID" });
    }

    const user = await User.findByIdAndDelete(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // TODO: Add cleanup of related data (posts, comments, etc.)

    return res.status(200).json({
      success: true,
      message: "User deleted successfully"
    });

  } catch (err) {
    console.error("Error deleting user:", err);
    return res.status(500).json({
      message: "Server error while deleting user",
      error: err.message
    });
  }
};

// Enhanced unlockUserAccount
const unlockUserAccount = async (req, res) => {
  try {
    const { userId } = req.params;

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
    ).select('-password');

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({
      success: true,
      message: "User account unlocked successfully",
      user
    });

  } catch (err) {
    console.error("Error unlocking account:", err);
    return res.status(500).json({
      message: "Server error while unlocking account",
      error: err.message
    });
  }
};

// Dashboard statistics
const getDashboardStats = async (req, res) => {
  try {
    // User statistics
    const totalUsers = await User.countDocuments();
    const newUsersThisWeek = await User.countDocuments({
      createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
    });
    
    const activeUsers = await User.countDocuments({
      lastActive: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
    });
    
    const userGrowth = await User.aggregate([
      {
        $group: {
          _id: {
            year: { $year: "$createdAt" },
            month: { $month: "$createdAt" },
            day: { $dayOfMonth: "$createdAt" }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { "_id.year": 1, "_id.month": 1, "_id.day": 1 } },
      { $limit: 30 }
    ]);

    // Login attempts
    const failedAttempts = await LoginAttempt.countDocuments({
      successful: false,
      createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
    });

    return res.status(200).json({
      success: true,
      stats: {
        users: {
          total: totalUsers,
          newThisWeek: newUsersThisWeek,
          active: activeUsers,
          growth: userGrowth
        },
        security: {
          failedAttempts24h: failedAttempts
        }
      }
    });

  } catch (err) {
    console.error("Error getting dashboard stats:", err);
    return res.status(500).json({
      message: "Server error while fetching dashboard stats",
      error: err.message
    });
  }
};

module.exports = {
  listAllUsers,
  getUserDetails,
  updateUser,
  deleteUser,
  unlockUserAccount,
  getDashboardStats
};
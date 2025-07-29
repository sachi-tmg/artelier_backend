// controllers/adminController.js

const User = require("../models/user");
const LoginAttempt = require("../models/login_attempt");
const Order = require("../models/order");
const AuditLog = require("../models/audit_log");
const AuditLogger = require("../services/audit_logger");
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
    const newUsersToday = await User.countDocuments({
      dateCreated: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) }
    });
    const newUsersThisWeek = await User.countDocuments({
      dateCreated: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
    });
    
    // Active users (users who have lastActive within 30 days)
    // Note: If lastActive is not being updated, we'll use a different approach
    let activeUsers = 0;
    try {
      activeUsers = await User.countDocuments({
        lastActive: { 
          $exists: true, 
          $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) 
        }
      });
    } catch (error) {
      // If lastActive field doesn't exist or isn't updated, count verified users as active
      console.log('LastActive field issue, using verified users as active:', error.message);
      activeUsers = await User.countDocuments({ isVerified: true, isBanned: false });
    }
    
    // Verified users
    const verifiedUsers = await User.countDocuments({ isVerified: true });
    const bannedUsers = await User.countDocuments({ isBanned: true });
    
    // User growth aggregation (last 30 days) - using dateCreated
    const userGrowth = await User.aggregate([
      {
        $match: {
          dateCreated: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$dateCreated" }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { "_id": 1 } }
    ]);

    // Fill in missing dates with zero count for better chart visualization
    const last30Days = [];
    for (let i = 29; i >= 0; i--) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      const dateStr = date.toISOString().split('T')[0];
      
      const existingData = userGrowth.find(item => item._id === dateStr);
      last30Days.push({
        _id: dateStr,
        count: existingData ? existingData.count : 0
      });
    }

    // Login attempts
    const failedAttempts = await LoginAttempt.countDocuments({
      successful: false,
      createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
    });

    const successfulLogins = await LoginAttempt.countDocuments({
      successful: true,
      createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
    });

    // User role breakdown
    const userRoles = await User.aggregate([
      {
        $group: {
          _id: { $ifNull: ["$role", "user"] }, // Handle null roles as 'user'
          count: { $sum: 1 }
        }
      }
    ]);

    // User status breakdown - fix the grouping to handle all combinations
    const userStatus = await User.aggregate([
      {
        $group: {
          _id: {
            verified: { $ifNull: ["$isVerified", false] },
            banned: { $ifNull: ["$isBanned", false] }
          },
          count: { $sum: 1 }
        }
      }
    ]);

    // Order statistics for dashboard
    const totalOrders = await Order.countDocuments();
    const newOrdersToday = await Order.countDocuments({
      createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) }
    });
    
    const newOrdersThisWeek = await Order.countDocuments({
      createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
    });
    
    const pendingOrders = await Order.countDocuments({ orderStatus: 'pending' });
    const processingOrders = await Order.countDocuments({ orderStatus: 'processing' });
    const shippedOrders = await Order.countDocuments({ orderStatus: 'shipped' });
    const deliveredOrders = await Order.countDocuments({ orderStatus: 'delivered' });
    const completedOrders = await Order.countDocuments({ orderStatus: 'completed' });
    const cancelledOrders = await Order.countDocuments({ orderStatus: 'cancelled' });
    
    // Revenue today
    const revenueToday = await Order.aggregate([
      {
        $match: {
          paymentStatus: "paid",
          createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) }
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: "$totalAmount" }
        }
      }
    ]);

    // Revenue this week
    const revenueThisWeek = await Order.aggregate([
      {
        $match: {
          paymentStatus: "paid",
          createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: "$totalAmount" }
        }
      }
    ]);

    // Payment status breakdown
    const paymentStatusBreakdown = await Order.aggregate([
      {
        $group: {
          _id: "$paymentStatus",
          count: { $sum: 1 }
        }
      }
    ]);

    // Add some debugging information
    console.log('Dashboard Debug Info:', {
      totalUsers,
      newUsersToday,
      newUsersThisWeek,
      activeUsers,
      userGrowthCount: userGrowth.length,
      sampleUserGrowth: userGrowth.slice(0, 3),
      totalOrders,
      revenueToday: revenueToday[0]?.total || 0
    });

    return res.status(200).json({
      success: true,
      stats: {
        users: {
          total: totalUsers,
          newToday: newUsersToday,
          newThisWeek: newUsersThisWeek,
          active: activeUsers,
          verified: verifiedUsers,
          banned: bannedUsers,
          growth: last30Days, // Complete 30-day data with zeros filled
          byRole: userRoles,
          byStatus: userStatus
        },
        orders: {
          total: totalOrders,
          newToday: newOrdersToday,
          newThisWeek: newOrdersThisWeek,
          pending: pendingOrders,
          processing: processingOrders,
          shipped: shippedOrders,
          delivered: deliveredOrders,
          completed: completedOrders,
          cancelled: cancelledOrders,
          revenueToday: revenueToday[0]?.total || 0,
          revenueThisWeek: revenueThisWeek[0]?.total || 0,
          byPaymentStatus: paymentStatusBreakdown
        },
        security: {
          failedAttempts24h: failedAttempts,
          successfulLogins24h: successfulLogins,
          loginSuccessRate: successfulLogins + failedAttempts > 0 
            ? Math.round((successfulLogins / (successfulLogins + failedAttempts)) * 100) 
            : 100
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

// ===================== ORDER MANAGEMENT FUNCTIONS =====================

// List all orders with filtering and pagination
const listAllOrders = async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 20, 
      search = '',
      paymentStatus = '',
      orderStatus = '',
      paymentMethod = '',
      deliveryOption = '',
      sortBy = 'createdAt',
      sortOrder = 'desc'
    } = req.query;
    
    const query = {};
    
    // Search filter - search by order ID, customer email, or user info
    if (search) {
      query.$or = [
        { orderId: { $regex: search, $options: 'i' } },
        { customerEmail: { $regex: search, $options: 'i' } }
      ];
    }
    
    // Status filters
    if (paymentStatus) {
      query.paymentStatus = paymentStatus;
    }
    
    if (orderStatus) {
      query.orderStatus = orderStatus;
    }
    
    if (paymentMethod) {
      query.paymentMethodUsed = paymentMethod;
    }
    
    if (deliveryOption) {
      query.deliveryOption = deliveryOption;
    }

    const sort = {};
    sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

    const orders = await Order.find(query)
      .populate('user', 'fullName email username profilePicture')
      .populate('items.creationId', 'title creationPicture price')
      .skip((page - 1) * limit)
      .limit(limit)
      .sort(sort);

    const totalOrders = await Order.countDocuments(query);

    return res.status(200).json({
      success: true,
      orders,
      total: totalOrders,
      page: parseInt(page),
      pages: Math.ceil(totalOrders / limit)
    });

  } catch (err) {
    console.error("Error listing orders:", err);
    return res.status(500).json({
      message: "Server error while fetching orders",
      error: err.message
    });
  }
};

// Get single order details
const getOrderDetails = async (req, res) => {
  try {
    const { orderId } = req.params;

    const order = await Order.findOne({ orderId })
      .populate('user', 'fullName email username profilePicture phone')
      .populate({
        path: 'items.creationId',
        select: 'title creationPicture price description userId',
        populate: {
          path: 'userId',
          select: 'fullName username'
        }
      })
      .populate('paymentRef');

    if (!order) {
      return res.status(404).json({ message: "Order not found" });
    }

    return res.status(200).json({
      success: true,
      order
    });

  } catch (err) {
    console.error("Error getting order details:", err);
    return res.status(500).json({
      message: "Server error while fetching order details",
      error: err.message
    });
  }
};

// Update order status
const updateOrderStatus = async (req, res) => {
  try {
    const { orderId } = req.params;
    const { orderStatus, paymentStatus, deliveryTrackingId, deliveryDate } = req.body;

    const updates = {};
    if (orderStatus !== undefined) updates.orderStatus = orderStatus;
    if (paymentStatus !== undefined) updates.paymentStatus = paymentStatus;
    if (deliveryTrackingId !== undefined) updates.deliveryTrackingId = deliveryTrackingId;
    if (deliveryDate !== undefined) updates.deliveryDate = deliveryDate;
    
    updates.updatedAt = Date.now();

    const order = await Order.findOneAndUpdate(
      { orderId },
      updates,
      { new: true }
    ).populate('user', 'fullName email username');

    if (!order) {
      return res.status(404).json({ message: "Order not found" });
    }

    return res.status(200).json({
      success: true,
      message: "Order updated successfully",
      order
    });

  } catch (err) {
    console.error("Error updating order:", err);
    return res.status(500).json({
      message: "Server error while updating order",
      error: err.message
    });
  }
};

// Delete/Cancel order
const deleteOrder = async (req, res) => {
  try {
    const { orderId } = req.params;

    const order = await Order.findOneAndDelete({ orderId });

    if (!order) {
      return res.status(404).json({ message: "Order not found" });
    }

    return res.status(200).json({
      success: true,
      message: "Order deleted successfully"
    });

  } catch (err) {
    console.error("Error deleting order:", err);
    return res.status(500).json({
      message: "Server error while deleting order",
      error: err.message
    });
  }
};

// Get order statistics for dashboard
const getOrderStats = async (req, res) => {
  try {
    // Basic order counts
    const totalOrders = await Order.countDocuments();
    const newOrdersToday = await Order.countDocuments({
      createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) }
    });
    
    const newOrdersThisWeek = await Order.countDocuments({
      createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
    });

    // Order status breakdown
    const orderStatusBreakdown = await Order.aggregate([
      {
        $group: {
          _id: "$orderStatus",
          count: { $sum: 1 }
        }
      }
    ]);

    // Payment status breakdown
    const paymentStatusBreakdown = await Order.aggregate([
      {
        $group: {
          _id: "$paymentStatus",
          count: { $sum: 1 }
        }
      }
    ]);

    // Revenue statistics
    const revenueStats = await Order.aggregate([
      {
        $match: { paymentStatus: "paid" }
      },
      {
        $group: {
          _id: null,
          totalRevenue: { $sum: "$totalAmount" },
          averageOrderValue: { $avg: "$totalAmount" }
        }
      }
    ]);

    // Daily revenue for the last 30 days
    const dailyRevenue = await Order.aggregate([
      {
        $match: {
          paymentStatus: "paid",
          createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$createdAt" }
          },
          revenue: { $sum: "$totalAmount" },
          orderCount: { $sum: 1 }
        }
      },
      { $sort: { "_id": 1 } }
    ]);

    // Top selling items
    const topSellingItems = await Order.aggregate([
      { $unwind: "$items" },
      {
        $group: {
          _id: "$items.creationId",
          title: { $first: "$items.title" },
          totalSold: { $sum: "$items.quantity" },
          totalRevenue: { $sum: { $multiply: ["$items.quantity", "$items.price"] } }
        }
      },
      { $sort: { totalSold: -1 } },
      { $limit: 10 },
      {
        $lookup: {
          from: "creations",
          localField: "_id",
          foreignField: "_id",
          as: "creation"
        }
      }
    ]);

    return res.status(200).json({
      success: true,
      stats: {
        orders: {
          total: totalOrders,
          newToday: newOrdersToday,
          newThisWeek: newOrdersThisWeek,
          byStatus: orderStatusBreakdown,
          byPaymentStatus: paymentStatusBreakdown
        },
        revenue: {
          total: revenueStats[0]?.totalRevenue || 0,
          average: revenueStats[0]?.averageOrderValue || 0,
          daily: dailyRevenue
        },
        topSelling: topSellingItems
      }
    });

  } catch (err) {
    console.error("Error getting order stats:", err);
    return res.status(500).json({
      message: "Server error while fetching order stats",
      error: err.message
    });
  }
};

// Get audit logs with filtering and pagination
const getAuditLogs = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 50,
      userId = null,
      action = null,
      status = null,
      ipAddress = null,
      startDate = null,
      endDate = null,
      searchUser = ''
    } = req.query;

    // Build query
    const query = {};
    
    if (userId) query.userId = userId;
    if (action) query.action = action;
    if (status) query.status = status;
    if (ipAddress) query.ipAddress = ipAddress;
    
    if (startDate || endDate) {
      query.timestamp = {};
      if (startDate) query.timestamp.$gte = new Date(startDate);
      if (endDate) query.timestamp.$lte = new Date(endDate);
    }

    // If searching by username, find user first
    if (searchUser) {
      const users = await User.find({
        $or: [
          { username: { $regex: searchUser, $options: 'i' } },
          { email: { $regex: searchUser, $options: 'i' } }
        ]
      }).select('_id');
      
      if (users.length > 0) {
        query.userId = { $in: users.map(u => u._id) };
      } else {
        // No users found, return empty result
        return res.status(200).json({
          success: true,
          logs: [],
          total: 0,
          page: parseInt(page),
          pages: 0
        });
      }
    }

    const result = await AuditLogger.getAuditLogs({
      ...query,
      page: parseInt(page),
      limit: parseInt(limit)
    });

    // Audit log admin access to audit logs
    await AuditLogger.logAdminAction(
      { _id: req.user._id, username: req.user.username, role: req.user.role },
      'audit_logs_accessed',
      '/api/admin/audit-logs',
      'GET',
      req.ip || req.connection.remoteAddress,
      req.headers['user-agent'],
      null,
      true,
      { filters: { userId, action, status, ipAddress, startDate, endDate } }
    );

    res.status(200).json({
      success: true,
      ...result
    });

  } catch (error) {
    console.error('Error fetching audit logs:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch audit logs',
      error: error.message
    });
  }
};

// Get security alerts (recent suspicious activities)
const getSecurityAlerts = async (req, res) => {
  try {
    const { limit = 20 } = req.query;
    
    const alerts = await AuditLogger.getSecurityAlerts(parseInt(limit));

    // Audit log admin access to security alerts
    await AuditLogger.logAdminAction(
      { _id: req.user._id, username: req.user.username, role: req.user.role },
      'security_alerts_accessed',
      '/api/admin/security-alerts',
      'GET',
      req.ip || req.connection.remoteAddress,
      req.headers['user-agent']
    );

    res.status(200).json({
      success: true,
      alerts
    });

  } catch (error) {
    console.error('Error fetching security alerts:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch security alerts',
      error: error.message
    });
  }
};

// Get audit statistics for dashboard
const getAuditStats = async (req, res) => {
  try {
    const { days = 7 } = req.query;
    const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

    // Get basic stats
    const totalLogs = await AuditLogger.getAuditLogs({
      startDate: startDate.toISOString(),
      page: 1,
      limit: 1
    });

    // Get action breakdown
    const actionStats = await AuditLog.aggregate([
      { $match: { timestamp: { $gte: startDate } } },
      { $group: { _id: '$action', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);

    // Get status breakdown
    const statusStats = await AuditLog.aggregate([
      { $match: { timestamp: { $gte: startDate } } },
      { $group: { _id: '$status', count: { $sum: 1 } } }
    ]);

    // Get IP address stats (top IPs)
    const ipStats = await AuditLog.aggregate([
      { $match: { timestamp: { $gte: startDate } } },
      { $group: { _id: '$ipAddress', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);

    // Get daily activity
    const dailyActivity = await AuditLog.aggregate([
      { $match: { timestamp: { $gte: startDate } } },
      {
        $group: {
          _id: {
            year: { $year: '$timestamp' },
            month: { $month: '$timestamp' },
            day: { $dayOfMonth: '$timestamp' }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1 } }
    ]);

    res.status(200).json({
      success: true,
      stats: {
        totalLogs: totalLogs.total,
        actionBreakdown: actionStats,
        statusBreakdown: statusStats,
        topIPs: ipStats,
        dailyActivity
      }
    });

  } catch (error) {
    console.error('Error fetching audit stats:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch audit statistics',
      error: error.message
    });
  }
};

// Get available action types for filtering
const getAuditActionTypes = async (req, res) => {
  try {
    const actionTypes = AuditLogger.getAvailableActions();
    
    res.status(200).json({
      success: true,
      actionTypes
    });
  } catch (err) {
    console.error("Error fetching action types:", err);
    res.status(500).json({
      success: false,
      message: "Error fetching action types",
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
  getDashboardStats,
  // Order management functions
  listAllOrders,
  getOrderDetails,
  updateOrderStatus,
  deleteOrder,
  getOrderStats,
  // Audit log functions
  getAuditLogs,
  getAuditActionTypes,
  getSecurityAlerts,
  getAuditStats
};
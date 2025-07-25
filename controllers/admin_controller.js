// controllers/adminController.js

const User = require("../models/user");
const LoginAttempt = require("../models/login_attempt");
const Order = require("../models/order");
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
    
    // Check if lastActive field exists before querying
    const activeUsers = await User.countDocuments({
      lastActive: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
    });
    
    // Simplified user growth aggregation
    const userGrowth = await User.aggregate([
      {
        $match: {
          createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$createdAt" }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { "_id": 1 } },
      { $limit: 30 }
    ]);

    // Login attempts
    const failedAttempts = await LoginAttempt.countDocuments({
      successful: false,
      createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
    });

    // User role breakdown
    const userRoles = await User.aggregate([
      {
        $group: {
          _id: "$role",
          count: { $sum: 1 }
        }
      }
    ]);

    // User status breakdown
    const userStatus = await User.aggregate([
      {
        $group: {
          _id: {
            verified: "$isVerified",
            banned: "$isBanned"
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
    
    const pendingOrders = await Order.countDocuments({ orderStatus: 'pending' });
    const completedOrders = await Order.countDocuments({ orderStatus: 'completed' });
    
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

    return res.status(200).json({
      success: true,
      stats: {
        users: {
          total: totalUsers,
          newThisWeek: newUsersThisWeek,
          active: activeUsers,
          growth: userGrowth,
          byRole: userRoles,
          byStatus: userStatus
        },
        orders: {
          total: totalOrders,
          newToday: newOrdersToday,
          pending: pendingOrders,
          completed: completedOrders,
          revenueToday: revenueToday[0]?.total || 0
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
  getOrderStats
};
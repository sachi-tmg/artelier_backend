const AuditLog = require('../models/audit_log');
const User = require('../models/user');
const { v4: uuidv4 } = require('uuid');

class AuditLogger {
  
  // User-friendly action mapping for non-technical admins
  static getActionDisplayName(action, details = {}) {
    const actionMap = {
      // Authentication Actions
      'login_attempt': 'User Login',
      'login_success': 'Successful Login',
      'login_failure': 'Failed Login',
      'mfa_attempt': 'Two-Factor Authentication',
      'mfa_success': 'Two-Factor Verification Success',
      'mfa_failure': 'Two-Factor Verification Failed',
      'logout': 'User Logout',
      
      // Account Management
      'account_created': 'Account Registration',
      'account_locked': 'Account Locked',
      'account_unlocked': 'Account Unlocked',
      'account_deleted': 'Account Deleted',
      'email_verified': 'Email Verification',
      
      // Password Management
      'password_changed': 'Password Changed',
      'password_reset_requested': 'Password Reset Requested',
      'password_reset_completed': 'Password Reset Completed',
      'password_expired': 'Password Expired',
      'force_password_change': 'Admin Forced Password Change',
      
      // Profile Management
      'profile_updated': 'Profile Updated',
      'profile_picture_uploaded': 'Profile Picture Changed',
      'cover_picture_uploaded': 'Cover Picture Changed',
      
      // Admin Actions
      'admin_action_performed': details.adminAction ? `Admin: ${details.adminAction}` : 'Admin Action',
      'user_role_changed': 'User Role Changed',
      'user_banned': 'User Banned',
      'user_unbanned': 'User Unbanned',
      
      // Security Events
      'suspicious_activity': 'Suspicious Activity Detected',
      'brute_force_attempt': 'Brute Force Attack Detected',
      'rate_limit_exceeded': 'Rate Limit Exceeded',
      'unauthorized_access': 'Unauthorized Access Attempt',
      
      // System Access
      'resource_accessed': 'System Access',
      'file_uploaded': 'File Upload',
      'file_downloaded': 'File Download',
      'data_export': 'Data Export',
      
      // Social Features
      'user_followed': 'User Followed',
      'user_unfollowed': 'User Unfollowed',
      'content_created': 'Content Created',
      'content_updated': 'Content Updated',
      'content_deleted': 'Content Deleted',
      
      // Payment & Orders
      'payment_initiated': 'Payment Started',
      'payment_completed': 'Payment Completed',
      'payment_failed': 'Payment Failed',
      'order_created': 'Order Created',
      'order_cancelled': 'Order Cancelled'
    };
    
    return actionMap[action] || action.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  }
  
  // Get status display with icons/colors for better UI
  static getStatusDisplay(status) {
    const statusMap = {
      'success': { text: 'Success', icon: '✅', color: 'green' },
      'failure': { text: 'Failed', icon: '❌', color: 'red' },
      'warning': { text: 'Warning', icon: '⚠️', color: 'orange' },
      'info': { text: 'Info', icon: 'ℹ️', color: 'blue' }
    };
    
    return statusMap[status] || { text: status, icon: '', color: 'gray' };
  }
  
  /**
   * Create an audit log entry
   * @param {Object} logData - The audit log data
   * @param {string} logData.action - The action being performed
   * @param {string} logData.resource - The resource/endpoint being accessed
   * @param {string} logData.method - HTTP method
   * @param {string} logData.status - success/failure/warning/info
   * @param {Object} logData.user - User information (optional)
   * @param {string} logData.ipAddress - Client IP address
   * @param {string} logData.userAgent - Client user agent
   * @param {Object} logData.details - Additional context (optional)
   * @param {string} logData.errorMessage - Error message if applicable (optional)
   * @param {number} logData.statusCode - HTTP status code (optional)
   */
  static async log({
    action,
    resource,
    method,
    status,
    user = null,
    ipAddress,
    userAgent = null,
    details = null,
    errorMessage = null,
    statusCode = null,
    sessionId = null,
    requestId = null
  }) {
    try {
      // Generate user-friendly action name
      const actionDisplayName = this.getActionDisplayName(action, details);
      
      const auditEntry = new AuditLog({
        userId: user?._id || user?.userId,
        username: user?.username,
        userRole: user?.role || 'anonymous',
        action,
        actionDisplayName, // Add user-friendly display name
        resource,
        method,
        ipAddress,
        userAgent,
        status,
        statusCode,
        details,
        errorMessage,
        sessionId,
        requestId: requestId || uuidv4(),
        timestamp: new Date()
      });

      await auditEntry.save();
      
      // Log critical security events to console for immediate attention
      if (status === 'failure' && this.isCriticalSecurityEvent(action)) {
        console.warn(`🚨 SECURITY ALERT: ${action} failed for user ${user?.username || 'anonymous'} from IP ${ipAddress}`);
      }
      
    } catch (error) {
      // Don't let audit logging failures break the main application
      console.error('Failed to create audit log entry:', error);
    }
  }

  // Convenience methods for common scenarios
  static async logLogin(user, ipAddress, userAgent, success, errorMessage = null) {
    await this.log({
      action: success ? 'login_success' : 'login_failure',
      resource: '/api/user/login',
      method: 'POST',
      status: success ? 'success' : 'failure',
      user,
      ipAddress,
      userAgent,
      errorMessage,
      details: success ? { loginTime: new Date() } : null
    });
  }

  static async logMfaAttempt(user, ipAddress, userAgent, success, errorMessage = null) {
    await this.log({
      action: success ? 'mfa_success' : 'mfa_failure',
      resource: '/api/user/verify-mfa',
      method: 'POST',
      status: success ? 'success' : 'failure',
      user,
      ipAddress,
      userAgent,
      errorMessage
    });
  }

  static async logPasswordChange(user, ipAddress, userAgent, success, errorMessage = null) {
    await this.log({
      action: 'password_changed',
      resource: '/api/user/update-password',
      method: 'PUT',
      status: success ? 'success' : 'failure',
      user,
      ipAddress,
      userAgent,
      errorMessage,
      details: { passwordChangedAt: new Date() }
    });
  }

  static async logProfileUpdate(user, ipAddress, userAgent, updatedFields, success = true) {
    await this.log({
      action: 'profile_updated',
      resource: '/api/user/update-profile',
      method: 'PUT',
      status: success ? 'success' : 'failure',
      user,
      ipAddress,
      userAgent,
      details: { updatedFields }
    });
  }

  static async logAccountCreation(user, ipAddress, userAgent, success, errorMessage = null) {
    await this.log({
      action: 'account_created',
      resource: '/api/user/registerUser',
      method: 'POST',
      status: success ? 'success' : 'failure',
      user,
      ipAddress,
      userAgent,
      errorMessage,
      details: { registrationTime: new Date() }
    });
  }

  static async logAdminAction(admin, action, resource, method, ipAddress, userAgent, targetUser = null, success = true, details = null) {
    await this.log({
      action: 'admin_action_performed',
      resource,
      method,
      status: success ? 'success' : 'failure',
      user: admin,
      ipAddress,
      userAgent,
      details: {
        adminAction: action,
        targetUser: targetUser?.username || targetUser?._id,
        ...details
      }
    });
  }

  static async logSuspiciousActivity(user, action, ipAddress, userAgent, details) {
    await this.log({
      action: 'suspicious_activity',
      resource: details.resource || 'unknown',
      method: details.method || 'unknown',
      status: 'warning',
      user,
      ipAddress,
      userAgent,
      details: {
        suspiciousAction: action,
        ...details
      }
    });
  }

  static async logRateLimitExceeded(ipAddress, userAgent, resource, details = null) {
    await this.log({
      action: 'rate_limit_exceeded',
      resource,
      method: 'ANY',
      status: 'warning',
      user: null,
      ipAddress,
      userAgent,
      details
    });
  }

  static async logFileOperation(user, action, fileName, ipAddress, userAgent, success = true, errorMessage = null) {
    await this.log({
      action: action, // 'file_uploaded', 'file_deleted', etc.
      resource: '/api/file-operation',
      method: 'POST',
      status: success ? 'success' : 'failure',
      user,
      ipAddress,
      userAgent,
      errorMessage,
      details: { fileName, operation: action }
    });
  }

  static async logOrderAction(user, orderId, action, ipAddress, userAgent, details = null) {
    await this.log({
      action: action, // 'order_placed', 'order_updated', etc.
      resource: '/api/orders',
      method: 'POST',
      status: 'success',
      user,
      ipAddress,
      userAgent,
      details: { orderId, ...details }
    });
  }

  // Helper method to identify critical security events
  static isCriticalSecurityEvent(action) {
    const criticalEvents = [
      'login_failure',
      'mfa_failure', 
      'unauthorized_access_attempt',
      'privilege_escalation_attempt',
      'suspicious_activity',
      'account_locked',
      'rate_limit_exceeded'
    ];
    return criticalEvents.includes(action);
  }

  // Method to get audit logs with filtering and user-friendly display
  static async getAuditLogs({
    userId = null,
    action = null,
    status = null,
    ipAddress = null,
    startDate = null,
    endDate = null,
    page = 1,
    limit = 50
  }) {
    try {
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

      const logs = await AuditLog.find(query)
        .populate('userId', 'username email')
        .sort({ timestamp: -1 })
        .skip((page - 1) * limit)
        .limit(limit);

      // Add user-friendly display names and status info
      const enhancedLogs = logs.map(log => {
        const logObj = log.toObject();
        logObj.actionDisplayName = this.getActionDisplayName(log.action, log.details);
        logObj.statusDisplay = this.getStatusDisplay(log.status);
        
        // Add formatted timestamp for easier reading
        logObj.formattedTimestamp = log.timestamp.toLocaleString();
        
        // Simplify user info for display
        if (logObj.userId) {
          logObj.userDisplayName = logObj.userId.username || logObj.userId.email || 'Unknown User';
        } else {
          logObj.userDisplayName = logObj.username || 'Anonymous';
        }
        
        return logObj;
      });

      const total = await AuditLog.countDocuments(query);

      return {
        logs: enhancedLogs,
        total,
        page,
        pages: Math.ceil(total / limit)
      };
    } catch (error) {
      console.error('Error fetching audit logs:', error);
      throw error;
    }
  }

  // Method to get security alerts (failed attempts, suspicious activities)
  static async getSecurityAlerts(limit = 20) {
    try {
      const alerts = await AuditLog.find({
        $or: [
          { status: 'failure' },
          { action: 'suspicious_activity' },
          { action: 'rate_limit_exceeded' },
          { action: 'unauthorized_access_attempt' }
        ]
      })
      .populate('userId', 'username email')
      .sort({ timestamp: -1 })
      .limit(limit);

      return alerts;
    } catch (error) {
      console.error('Error fetching security alerts:', error);
      throw error;
    }
  }

  // Get available action types for admin filters
  static getAvailableActions() {
    return [
      { value: 'login_success', label: 'Successful Login' },
      { value: 'login_failure', label: 'Failed Login' },
      { value: 'mfa_success', label: 'Two-Factor Success' },
      { value: 'mfa_failure', label: 'Two-Factor Failed' },
      { value: 'account_created', label: 'Account Registration' },
      { value: 'password_changed', label: 'Password Changed' },
      { value: 'password_reset_requested', label: 'Password Reset Requested' },
      { value: 'profile_updated', label: 'Profile Updated' },
      { value: 'admin_action_performed', label: 'Admin Action' },
      { value: 'suspicious_activity', label: 'Suspicious Activity' },
      { value: 'account_locked', label: 'Account Locked' },
      { value: 'file_uploaded', label: 'File Upload' },
      { value: 'user_followed', label: 'User Followed' },
      { value: 'payment_completed', label: 'Payment Completed' },
      { value: 'order_created', label: 'Order Created' }
    ];
  }

  // Get log statistics for admin dashboard
  static async getLogStatistics(days = 7) {
    try {
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - days);

      const stats = await AuditLog.aggregate([
        {
          $match: {
            timestamp: { $gte: startDate }
          }
        },
        {
          $group: {
            _id: '$action',
            count: { $sum: 1 },
            successCount: {
              $sum: { $cond: [{ $eq: ['$status', 'success'] }, 1, 0] }
            },
            failureCount: {
              $sum: { $cond: [{ $eq: ['$status', 'failure'] }, 1, 0] }
            }
          }
        },
        {
          $sort: { count: -1 }
        }
      ]);

      // Add user-friendly names to stats
      const enhancedStats = stats.map(stat => ({
        ...stat,
        actionDisplayName: this.getActionDisplayName(stat._id),
        successRate: stat.count > 0 ? ((stat.successCount / stat.count) * 100).toFixed(1) : 0
      }));

      return enhancedStats;
    } catch (error) {
      console.error('Error fetching log statistics:', error);
      throw error;
    }
  }
}

module.exports = AuditLogger;

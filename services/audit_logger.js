const AuditLog = require('../models/audit_log');
const User = require('../models/user');
const { v4: uuidv4 } = require('uuid');

class AuditLogger {
  
  // Only log important user actions, not technical noise
  static IMPORTANT_ACTIONS_ONLY = [
    // Authentication (only results, not attempts)
    'login_success', 'login_failed', 'logout',
    'password_reset_success', 'password_changed',
    
    // Account management
    'account_created', 'account_verified', 'account_locked', 'account_deleted',
    'profile_updated',
    
    // Admin actions
    'admin_action_performed', 'user_account_modified',
    
    // Content actions
    'content_created', 'content_updated', 'content_deleted',
    'comment_posted', 'file_uploaded',
    
    // Order actions ✅ ADDED
    'order_placed', 'order_viewed', 'order_updated', 'order_cancelled',
    'order_creation_failed', 'order_access_failed', 'order_access_unauthorized',
    'orders_list_accessed', 'order_status_updated',
    
    // Security (only serious events)
    'suspicious_activity'
  ];

  // User-friendly action mapping for non-technical admins
  static ACTION_DISPLAY_NAMES = {
    // Authentication
    'login_success': 'User Login',
    'login_failed': 'Failed Login Attempt', 
    'logout': 'User Logout',
    'password_changed': 'Password Changed',
    'password_reset_success': 'Password Reset',
    
    // Account management
    'account_created': 'Account Registration',
    'account_verified': 'Email Verified',
    'account_locked': 'Account Locked',
    'account_deleted': 'Account Deleted',
    'profile_updated': 'Profile Updated',
    
    // Content
    'content_created': 'Content Created',
    'content_updated': 'Content Updated',
    'content_deleted': 'Content Deleted',
    'comment_posted': 'Comment Posted',
    'file_uploaded': 'File Uploaded',
    
    // Orders ✅ ADDED
    'order_placed': 'Order Placed',
    'order_viewed': 'Order Viewed',
    'order_updated': 'Order Updated',
    'order_cancelled': 'Order Cancelled',
    'order_creation_failed': 'Order Creation Failed',
    'order_access_failed': 'Order Access Failed',
    'order_access_unauthorized': 'Unauthorized Order Access',
    'orders_list_accessed': 'Orders List Viewed',
    'order_status_updated': 'Order Status Updated',
    
    // Admin
    'admin_action_performed': 'Admin Action',
    'user_account_modified': 'User Account Modified',
    
    // Security
    'suspicious_activity': 'Security Alert'
  };

  static getActionDisplayName(action) {
    return this.ACTION_DISPLAY_NAMES[action] || action.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  }
  
  /**
   * Create an audit log entry - Only logs important actions
   * @param {Object} logData - The audit log data
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
      // Skip technical/noise actions - only log important user actions
      if (!this.IMPORTANT_ACTIONS_ONLY.includes(action)) {
        //console.log(`🚫 [AUDIT SKIP] Action '${action}' not in whitelist, skipping...`);
        return; // Don't log unimportant actions
      }

      //console.log(`✅ [AUDIT PROCESS] Logging action '${action}' to MongoDB...`);

      const auditEntry = new AuditLog({
        userId: user?._id || user?.userId,
        username: user?.username,
        userRole: user?.role || 'anonymous',
        action,
        actionDisplayName: this.getActionDisplayName(action),
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

      const savedEntry = await auditEntry.save();
      //console.log(`🎉 [AUDIT SUCCESS] Saved audit log with ID: ${savedEntry._id}`);
      
      // Log critical security events to console for immediate attention
      if (status === 'failure' && this.isCriticalSecurityEvent(action)) {
        console.warn(`🚨 SECURITY ALERT: ${action} failed for user ${user?.username || 'anonymous'} from IP ${ipAddress}`);
      }
      
    } catch (error) {
      // Don't let audit logging failures break the main application
      console.error('❌ [AUDIT ERROR] Failed to create audit log entry:', error);
      console.error('❌ [AUDIT ERROR] Details:', error.message);
    }
  }

  // Convenience methods for common scenarios
  static async logLogin(user, ipAddress, userAgent, success, errorMessage = null) {
    await this.log({
      action: success ? 'login_success' : 'login_failed',
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
    // Only log final MFA result, not intermediate steps
    if (success) {
      await this.log({
        action: 'login_success',
        resource: '/api/user/verify-mfa',
        method: 'POST',
        status: 'success',
        user,
        ipAddress,
        userAgent,
        details: { mfaCompleted: true, loginTime: new Date() }
      });
    } else {
      await this.log({
        action: 'login_failed',
        resource: '/api/user/verify-mfa',
        method: 'POST',
        status: 'failure',
        user,
        ipAddress,
        userAgent,
        errorMessage,
        details: { mfaFailed: true }
      });
    }
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
      action: action, // 'order_placed', 'order_viewed', 'order_updated', etc.
      resource: orderId ? `/api/orders/${orderId}` : '/api/orders',
      method: this.getMethodFromAction(action),
      status: this.getStatusFromAction(action),
      user,
      ipAddress,
      userAgent,
      details: { orderId, ...details }
    });
  }

  // Helper method to determine HTTP method from action
  static getMethodFromAction(action) {
    if (action.includes('placed') || action.includes('creation')) return 'POST';
    if (action.includes('viewed') || action.includes('accessed') || action.includes('list')) return 'GET';
    if (action.includes('updated') || action.includes('status')) return 'PUT';
    if (action.includes('cancelled') || action.includes('deleted')) return 'DELETE';
    return 'POST'; // default
  }

  // Helper method to determine status from action
  static getStatusFromAction(action) {
    if (action.includes('failed') || action.includes('error') || action.includes('unauthorized')) return 'failure';
    return 'success';
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

  // Method to get audit logs with filtering
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

      const total = await AuditLog.countDocuments(query);

      return {
        logs,
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
}

module.exports = AuditLogger;

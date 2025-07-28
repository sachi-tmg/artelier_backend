const AuditLog = require('../models/audit_log');
const User = require('../models/user');
const { v4: uuidv4 } = require('uuid');

class AuditLogger {
  
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
      const auditEntry = new AuditLog({
        userId: user?._id || user?.userId,
        username: user?.username,
        userRole: user?.role || 'anonymous',
        action,
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
      action: 'password_change',
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

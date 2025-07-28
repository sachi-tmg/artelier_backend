const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  // User information
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'users',
    required: false // Some actions might be anonymous
  },
  username: {
    type: String,
    required: false
  },
  userRole: {
    type: String,
    enum: ['user', 'admin', 'anonymous'],
    default: 'anonymous'
  },

  // Action details
  action: {
    type: String,
    required: true,
    enum: [
      // Authentication actions
      'login_attempt', 'login_success', 'login_failure', 'logout',
      'mfa_attempt', 'mfa_success', 'mfa_failure',
      'password_reset_request', 'password_reset_success', 'password_change',
      
      // Account management
      'account_created', 'account_verified', 'account_locked', 'account_unlocked', 'account_banned',
      'profile_updated', 'profile_picture_uploaded', 'cover_picture_uploaded',
      
      // Security events
      'suspicious_activity', 'rate_limit_exceeded', 'unauthorized_access_attempt',
      'admin_action_performed', 'privilege_escalation_attempt',
      
      // Content actions
      'creation_uploaded', 'creation_updated', 'creation_deleted',
      'order_placed', 'order_updated', 'payment_processed',
      'comment_posted', 'like_added', 'follow_action',
      
      // Admin actions
      'user_search', 'user_list_accessed', 'dashboard_accessed',
      'order_status_changed', 'user_account_modified',
      
      // File operations
      'file_uploaded', 'file_deleted', 'file_accessed',
      
      // Generic resource operations (for middleware)
      'resource_accessed', 'resource_created', 'resource_updated', 'resource_deleted', 'unknown_action'
    ]
  },
  
  // Request details
  resource: {
    type: String, // e.g., '/api/user/login', '/api/admin/users'
    required: true
  },
  method: {
    type: String,
    enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    required: true
  },
  
  // Network information
  ipAddress: {
    type: String,
    required: true
  },
  userAgent: {
    type: String,
    required: false
  },
  
  // Status and result
  status: {
    type: String,
    enum: ['success', 'failure', 'warning', 'info'],
    required: true
  },
  statusCode: {
    type: Number,
    required: false
  },
  
  // Additional context
  details: {
    type: mongoose.Schema.Types.Mixed, // Flexible object for additional data
    required: false
  },
  errorMessage: {
    type: String,
    required: false
  },
  
  // Metadata
  sessionId: {
    type: String,
    required: false
  },
  requestId: {
    type: String,
    required: false
  },
  
  // Timestamps
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  }
}, {
  timestamps: true,
  // Auto-delete logs older than 90 days for storage management
  expireAfterSeconds: 90 * 24 * 60 * 60 // 90 days
});

// Indexes for efficient querying
auditLogSchema.index({ userId: 1, timestamp: -1 });
auditLogSchema.index({ action: 1, timestamp: -1 });
auditLogSchema.index({ ipAddress: 1, timestamp: -1 });
auditLogSchema.index({ status: 1, timestamp: -1 });
auditLogSchema.index({ resource: 1, method: 1, timestamp: -1 });

module.exports = mongoose.model('AuditLog', auditLogSchema);

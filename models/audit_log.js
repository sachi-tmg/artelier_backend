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
      // Authentication
      'login_attempt', 'login_success', 'logout',
      'password_reset_request', 'password_reset_success',

      // Account management
      'account_created', 'account_verified', 'account_locked',
      'profile_updated',

      // Security
      'suspicious_activity', 'unauthorized_access_attempt', 'rate_limit_exceeded',

      // Content actions
      'content_created', 'content_updated', 'content_deleted',
      'comment_posted', 'like_added',

      // Admin
      'dashboard_accessed', 'user_account_modified',

      // File operations
      'file_uploaded', 'file_downloaded',

      // Fallback
      'unknown_action'
    ]
  },
  
  // User-friendly action name for admin interface
  actionDisplayName: {
    type: String,
    required: false // Will be generated automatically
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

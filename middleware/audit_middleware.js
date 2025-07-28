const AuditLogger = require('../services/audit_logger');
const { v4: uuidv4 } = require('uuid');

// Middleware to automatically log API requests
const auditMiddleware = (options = {}) => {
  return async (req, res, next) => {
    // Generate a unique request ID for tracking
    req.requestId = uuidv4();
    
    // Store original methods
    const originalSend = res.send;
    const originalJson = res.json;
    
    // Capture request start time
    const startTime = Date.now();
    
    // Extract request information
    const ipAddress = req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
                     req.headers['x-real-ip'] ||
                     req.connection.remoteAddress ||
                     req.socket.remoteAddress ||
                     req.ip ||
                     'unknown';
    
    // Convert IPv6 loopback to IPv4 for better readability
    const cleanIpAddress = ipAddress === '::1' ? '127.0.0.1' : ipAddress;
    const userAgent = req.headers['user-agent'];
    const resource = req.originalUrl || req.url;
    const method = req.method;
    
    // Skip logging for certain paths if specified
    const skipPaths = options.skipPaths || ['/health', '/ping', '/favicon.ico'];
    if (skipPaths.some(path => resource.startsWith(path))) {
      return next();
    }

    // Override response methods to capture response data
    let responseBody = null;
    let statusCode = null;

    res.send = function(data) {
      responseBody = data;
      statusCode = res.statusCode;
      return originalSend.call(this, data);
    };

    res.json = function(data) {
      responseBody = data;
      statusCode = res.statusCode;
      return originalJson.call(this, data);
    };

    // Handle response completion
    res.on('finish', async () => {
      try {
        const duration = Date.now() - startTime;
        const user = req.user || null;
        
        // Determine the action based on the endpoint
        const action = determineAction(resource, method, statusCode);
        
        // Determine status based on HTTP status code
        const status = determineLogStatus(statusCode);
        
        // Prepare additional details
        const details = {
          duration,
          requestId: req.requestId,
          requestSize: req.headers['content-length'] || 0,
          responseSize: responseBody ? JSON.stringify(responseBody).length : 0
        };

        // Add request body for certain actions (excluding sensitive data)
        if (shouldLogRequestBody(resource, method)) {
          details.requestBody = sanitizeRequestBody(req.body);
        }

        // Log the request
        await AuditLogger.log({
          action,
          resource,
          method,
          status,
          user,
          ipAddress: cleanIpAddress,
          userAgent,
          statusCode,
          details,
          errorMessage: status === 'failure' && responseBody?.message ? responseBody.message : null,
          requestId: req.requestId
        });

        // Log specific security events
        await logSpecificSecurityEvents(req, res, user, cleanIpAddress, userAgent, statusCode, responseBody);

      } catch (error) {
        console.error('Audit middleware error:', error);
        // Don't break the request flow due to logging errors
      }
    });

    next();
  };
};

// Determine action type based on endpoint and method
function determineAction(resource, method, statusCode) {
  // Authentication and authorization
  if (resource.includes('/login')) return 'login_attempt';
  if (resource.includes('/registerUser')) return 'user_registration';
  if (resource.includes('/logout')) return 'logout';
  if (resource.includes('/verify-email')) return 'email_verification';
  if (resource.includes('/reset-password')) return 'password_reset_request';
  if (resource.includes('/update-password')) return 'password_change';
  if (resource.includes('/verify-mfa')) return 'mfa_verification';
  
  // User management
  if (resource.includes('/get-user')) return 'user_profile_accessed';
  if (resource.includes('/users') && method === 'GET') return 'user_data_accessed';
  if (resource.includes('/users') && method === 'PUT') return 'user_data_updated';
  if (resource.includes('/users') && method === 'DELETE') return 'user_deleted';
  
  // Profile operations
  if (resource.includes('/update-profile')) return 'profile_updated';
  if (resource.includes('/upload-profile-picture')) return 'profile_picture_uploaded';
  if (resource.includes('/upload-cover-picture')) return 'cover_picture_uploaded';
  
  // Content operations
  if (resource.includes('/creation') && method === 'POST') return 'creation_uploaded';
  if (resource.includes('/creation') && method === 'PUT') return 'creation_updated';
  if (resource.includes('/creation') && method === 'DELETE') return 'creation_deleted';
  
  // Order operations
  if (resource.includes('/orders') && method === 'POST') return 'order_placed';
  if (resource.includes('/orders') && method === 'PUT') return 'order_updated';
  
  // Admin operations
  if (resource.includes('/admin')) return 'admin_action_performed';
  if (resource.includes('/dashboard')) return 'dashboard_accessed';
  if (resource.includes('/audit-logs')) return 'audit_logs_accessed';
  
  // File operations
  if (resource.includes('/upload')) return 'file_uploaded';
  
  // Social actions
  if (resource.includes('/like')) return 'like_added';
  if (resource.includes('/follow')) return 'follow_action';
  if (resource.includes('/comment')) return 'comment_posted';
  
  // Generic actions based on HTTP method
  switch (method) {
    case 'GET': return 'resource_accessed';
    case 'POST': return 'resource_created';
    case 'PUT': case 'PATCH': return 'resource_updated';
    case 'DELETE': return 'resource_deleted';
    default: return 'unknown_action';
  }
}

// Determine log status based on HTTP status code
function determineLogStatus(statusCode) {
  if (statusCode >= 200 && statusCode < 300) return 'success';
  if (statusCode >= 300 && statusCode < 400) return 'info';
  if (statusCode >= 400 && statusCode < 500) return 'warning';
  if (statusCode >= 500) return 'failure';
  return 'info';
}

// Determine if request body should be logged
function shouldLogRequestBody(resource, method) {
  // Log body for these endpoints (excluding sensitive auth endpoints)
  const logBodyPaths = [
    '/api/user/update-profile',
    '/api/creation',
    '/api/admin'
  ];
  
  // Don't log body for sensitive endpoints
  const sensitiveEndpoints = [
    '/login',
    '/registerUser',
    '/update-password',
    '/reset-password',
    '/verify-mfa'
  ];
  
  if (sensitiveEndpoints.some(path => resource.includes(path))) {
    return false;
  }
  
  return method !== 'GET' && logBodyPaths.some(path => resource.includes(path));
}

// Sanitize request body to remove sensitive information
function sanitizeRequestBody(body) {
  if (!body || typeof body !== 'object') return body;
  
  const sensitiveFields = ['password', 'currentPassword', 'newPassword', 'token', 'otp', 'mfaOtp'];
  const sanitized = { ...body };
  
  sensitiveFields.forEach(field => {
    if (sanitized[field]) {
      sanitized[field] = '[REDACTED]';
    }
  });
  
  return sanitized;
}

// Log specific security events
async function logSpecificSecurityEvents(req, res, user, ipAddress, userAgent, statusCode, responseBody) {
  try {
    // Rate limit violations
    if (statusCode === 429) {
      await AuditLogger.logRateLimitExceeded(ipAddress, userAgent, req.originalUrl, {
        requestId: req.requestId,
        message: responseBody?.message
      });
    }

    // Unauthorized access attempts
    if (statusCode === 401 || statusCode === 403) {
      await AuditLogger.log({
        action: 'unauthorized_access_attempt',
        resource: req.originalUrl,
        method: req.method,
        status: 'warning',
        user,
        ipAddress,
        userAgent,
        statusCode,
        details: {
          requestId: req.requestId,
          attemptedResource: req.originalUrl,
          errorMessage: responseBody?.message
        }
      });
    }

    // Multiple failed login attempts from same IP
    if (req.originalUrl.includes('/login') && statusCode >= 400) {
      // This could trigger additional monitoring for brute force attacks
      console.warn(`⚠️  Failed login attempt from IP: ${ipAddress}`);
    }

  } catch (error) {
    console.error('Error logging specific security events:', error);
  }
}

module.exports = auditMiddleware;

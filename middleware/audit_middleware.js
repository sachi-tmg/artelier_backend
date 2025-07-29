const AuditLogger = require('../services/audit_logger');
const { v4: uuidv4 } = require('uuid');

// Selective audit middleware - only log important admin actions
const auditMiddleware = (options = {}) => {
  return async (req, res, next) => {
    // Only log admin endpoints - user actions are logged by their controllers
    if (!req.path.startsWith('/api/admin')) {
      return next(); // Skip logging for non-admin endpoints
    }
    
    // Generate a unique request ID for tracking
    req.requestId = uuidv4();
    
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
    
    // Store original response methods
    const originalSend = res.send;
    const originalJson = res.json;
    let statusCode = null;

    res.send = function(data) {
      statusCode = res.statusCode;
      return originalSend.call(this, data);
    };

    res.json = function(data) {
      statusCode = res.statusCode;
      return originalJson.call(this, data);
    };

    // Log after response completes
    res.on('finish', async () => {
      try {
        const duration = Date.now() - startTime;
        const user = req.user || null;
        
        // Log admin action
        await AuditLogger.log({
          action: 'admin_action_performed',
          resource,
          method,
          status: statusCode >= 400 ? 'failure' : 'success',
          user,
          ipAddress: cleanIpAddress,
          userAgent,
          statusCode,
          details: { 
            duration, 
            requestId: req.requestId,
            adminEndpoint: resource
          }
        });
      } catch (error) {
        console.error('Audit logging error:', error);
      }
    });

    next();
  };
};

module.exports = auditMiddleware;

// middleware/csrf_protection.js
const crypto = require('crypto');
const AuditLogger = require('../services/audit_logger');

// Store for CSRF tokens (in production, use Redis or database)
const csrfTokenStore = new Map();

// Generate a secure random token
const generateCSRFToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Middleware to generate and validate CSRF tokens
const csrfProtection = (options = {}) => {
  const {
    cookieName = 'csrf-token',
    headerName = 'x-csrf-token',
    skipMethods = ['GET', 'HEAD', 'OPTIONS'],
    tokenExpiry = 3600000, // 1 hour in milliseconds
    development = process.env.NODE_ENV === 'development'
  } = options;

  return (req, res, next) => {
    const method = req.method.toUpperCase();
    
    // COMPLETE DEVELOPMENT BYPASS - Remove this in production!
    if (development && process.env.DISABLE_CSRF === 'true') {
      console.log(`🚫 [DEV] CSRF completely disabled for ${req.method} ${req.path}`);
      return next();
    }
    
    // Skip CSRF for safe methods
    if (skipMethods.includes(method)) {
      return next();
    }

    // In development, completely disable CSRF for common problematic endpoints
    if (development) {
      const skipEndpoints = [
        '/api/user/me',
        '/api/creation/latest-creations', 
        '/api/user/profile',
        '/api/comments',
        '/api/comment/', // Any comment endpoint
        '/api/like/',    // Like endpoints
        '/api/favorite/',
        '/api/orders/'
      ];
      
      console.log(`🔍 [CSRF DEBUG] Checking path: ${req.path}, Method: ${req.method}`);
      const shouldSkip = skipEndpoints.some(endpoint => req.path.includes(endpoint));
      console.log(`🔍 [CSRF DEBUG] Should skip: ${shouldSkip}`);
      
      if (shouldSkip) {
        console.log(`🔧 [DEV] Completely skipping CSRF for ${req.path}`);
        return next();
      }
    }

    // Get token from multiple sources with better error handling
    const clientToken = req.headers[headerName] || req.body._csrf || req.query._csrf;
    
    if (!clientToken) {
      // More descriptive error response
      const errorResponse = {
        success: false,
        message: 'CSRF token missing. Please refresh and try again.',
        code: 'CSRF_MISSING',
        hint: 'Make sure your request includes the x-csrf-token header'
      };

      // Only log in production to reduce noise
      if (!development) {
        AuditLogger.log({
          action: 'csrf_validation_failed',
          resource: req.originalUrl,
          method: req.method,
          status: 'failure',
          user: req.user || null,
          ipAddress: req.ip || req.connection.remoteAddress,
          userAgent: req.headers['user-agent'],
          details: { reason: 'csrf_token_missing' }
        }).catch(err => console.error('Audit log error:', err));
      }

      return res.status(403).json(errorResponse);
    }

    // Validate token
    const storedTokenData = csrfTokenStore.get(clientToken);
    
    if (!storedTokenData) {
      const errorResponse = {
        success: false,
        message: 'Invalid CSRF token. Please refresh and try again.',
        code: 'CSRF_INVALID',
        hint: 'Your session may have expired'
      };

      // Only log in production
      if (!development) {
        AuditLogger.log({
          action: 'csrf_validation_failed',
          resource: req.originalUrl,
          method: req.method,
          status: 'failure',
          user: req.user || null,
          ipAddress: req.ip || req.connection.remoteAddress,
          userAgent: req.headers['user-agent'],
          details: { reason: 'csrf_token_invalid' }
        }).catch(err => console.error('Audit log error:', err));
      }

      return res.status(403).json(errorResponse);
    }

    // Check if token has expired
    if (Date.now() > storedTokenData.expires) {
      csrfTokenStore.delete(clientToken);
      
      // Audit log expired CSRF token
      AuditLogger.log({
        action: 'csrf_token_expired',
        resource: req.originalUrl,
        method: req.method,
        status: 'failure',
        user: req.user || null,
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.headers['user-agent'],
        details: { reason: 'csrf_token_expired' }
      }).catch(err => console.error('Audit log error:', err));

      return res.status(403).json({
        success: false,
        message: 'CSRF token expired',
        code: 'CSRF_EXPIRED'
      });
    }

    // Validate session association (if user is authenticated)
    if (req.user && storedTokenData.userId !== req.user.userId) {
      // Audit log user mismatch
      AuditLogger.log({
        action: 'csrf_validation_failed',
        resource: req.originalUrl,
        method: req.method,
        status: 'failure',
        user: req.user || null,
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.headers['user-agent'],
        details: { reason: 'csrf_user_mismatch', tokenUserId: storedTokenData.userId }
      }).catch(err => console.error('Audit log error:', err));

      return res.status(403).json({
        success: false,
        message: 'CSRF token invalid for user',
        code: 'CSRF_USER_MISMATCH'
      });
    }

    // Token is valid, remove it (one-time use)
    csrfTokenStore.delete(clientToken);
    
    next();
  };
};

// Endpoint to get CSRF token
const getCSRFToken = (req, res) => {
  const token = generateCSRFToken();
  const expires = Date.now() + 3600000; // 1 hour
  
  // Store token with expiry and user association
  csrfTokenStore.set(token, {
    expires,
    userId: req.user ? req.user.userId : null,
    createdAt: Date.now(),
    ipAddress: req.ip || req.connection.remoteAddress
  });

  // Audit log CSRF token generation
  AuditLogger.log({
    action: 'csrf_token_generated',
    resource: '/api/csrf/token',
    method: 'GET',
    status: 'success',
    user: req.user || null,
    ipAddress: req.ip || req.connection.remoteAddress,
    userAgent: req.headers['user-agent'],
    details: { tokenExpires: new Date(expires).toISOString() }
  }).catch(err => console.error('Audit log error:', err));

  // Set token in cookie (for double submit cookie pattern)
  res.cookie('csrf-token', token, {
    httpOnly: false, // Client needs to read this
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 3600000 // 1 hour
  });

  res.json({
    success: true,
    csrfToken: token,
    expires: new Date(expires).toISOString()
  });
};

// Cleanup expired tokens (call this periodically)
const cleanupExpiredTokens = () => {
  const now = Date.now();
  for (const [token, data] of csrfTokenStore.entries()) {
    if (now > data.expires) {
      csrfTokenStore.delete(token);
    }
  }
};

// Cleanup every 5 minutes
setInterval(cleanupExpiredTokens, 5 * 60 * 1000);

module.exports = {
  csrfProtection,
  getCSRFToken,
  cleanupExpiredTokens
};

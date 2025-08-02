// middleware/sanitization_middleware.js
const InputSanitizer = require('../utils/sanitizer');
const AuditLogger = require('../services/audit_logger');

// Define sanitization schemas for different routes
const sanitizationSchemas = {
  // User registration/profile
  user: {
    fullName: { type: 'text', maxLength: 100, required: true },
    username: { type: 'username', maxLength: 30, required: true },
    email: { type: 'email', required: true },
    bio: { type: 'text', maxLength: 500 },
    website: { type: 'url' },
    location: { type: 'text', maxLength: 100 }
  },
  
  // User registration (signup)
  register: {
    fullName: { type: 'text', maxLength: 100, required: true },
    email: { type: 'email', required: true },
    password: { type: 'password', required: true },
    confirmPassword: { type: 'password' },
    username: { type: 'username', maxLength: 30 }
  },
  
  // User login
  login: {
    email: { type: 'email', required: true },
    password: { type: 'password', required: true },
    rememberMe: { type: 'boolean' },
    mfaCode: { type: 'text', maxLength: 10 },
    backupCode: { type: 'text', maxLength: 20 }
  },
  
  // Comments
  comment: {
    comment: { type: 'text', maxLength: 500, required: true },
    creationId: { type: 'text', required: true },
    parentId: { type: 'objectid' }
  },
  
  // Creations
  creation: {
    title: { type: 'text', maxLength: 200, required: true },
    description: { type: 'text', maxLength: 2000 },
    des: { type: 'text', maxLength: 2000 }, // Alternative field name
    category: { type: 'text', maxLength: 50, required: true },
    materials: { type: 'text', maxLength: 300 },
    dimension: { type: 'text', maxLength: 100 },
    price: { type: 'number', min: 0, max: 1000000 },
    forSale: { type: 'boolean' },
    tags: { type: 'text', maxLength: 200 }
  },
  
  // Contact form
  contact: {
    name: { type: 'text', maxLength: 100, required: true },
    email: { type: 'email', required: true },
    subject: { type: 'text', maxLength: 200, required: true },
    message: { type: 'text', maxLength: 1000, required: true }
  },
  
  // Search queries
  search: {
    query: { type: 'text', maxLength: 100 },
    q: { type: 'text', maxLength: 100 },
    search: { type: 'text', maxLength: 100 },
    category: { type: 'text', maxLength: 50 },
    sortBy: { type: 'text', maxLength: 20 },
    sort: { type: 'text', maxLength: 20 },
    order: { type: 'text', maxLength: 10 },
    page: { type: 'number', min: 1, max: 1000 },
    limit: { type: 'number', min: 1, max: 100 },
    tags: { type: 'text', maxLength: 200 },
    minPrice: { type: 'number', min: 0 },
    maxPrice: { type: 'number', min: 0, max: 1000000 }
  },
  
  // Password reset
  passwordReset: {
    email: { type: 'email', required: true },
    token: { type: 'text', maxLength: 100 },
    newPassword: { type: 'password', required: true },
    confirmPassword: { type: 'password', required: true }
  },
  
  // Profile update
  profileUpdate: {
    fullName: { type: 'text', maxLength: 100 },
    username: { type: 'username', maxLength: 30 },
    bio: { type: 'text', maxLength: 500 },
    website: { type: 'url' },
    location: { type: 'text', maxLength: 100 },
    phone: { type: 'text', maxLength: 20 },
    dateOfBirth: { type: 'date' }
  }
};

// Route-specific sanitization mapping
const routeSanitization = {
  // Authentication routes
  '/api/user/registerUser': 'register',
  '/api/user/register': 'register',
  '/api/user/signup': 'register',
  '/api/user/login': 'login',
  '/api/user/loginUser': 'login',
  '/api/user/signin': 'login',
  '/api/auth/login': 'login',
  
  // User management routes
  '/api/user/update-profile': 'profileUpdate',
  '/api/user/profile': 'profileUpdate',
  '/api/user/forgot-password': 'passwordReset',
  '/api/user/reset-password': 'passwordReset',
  
  // Content routes
  '/api/comments': 'comment',
  '/api/creation/createCreation': 'creation',
  '/api/creation/updateCreation': 'creation',
  
  // Utility routes
  '/api/contact': 'contact',
  '/api/search': 'search',
  '/api/creations/search': 'search',
  '/api/creation/search-creations': 'search',
  '/api/creation/count-search-creations': 'search',
  '/api/user/search-users': 'search',
  '/api/users/search': 'search'
};

class SanitizationMiddleware {
  
  // Main sanitization middleware
  static sanitizeInput() {
    return (req, res, next) => {
      try {
        // Skip sanitization for certain routes or methods
        if (this.shouldSkipSanitization(req)) {
          return next();
        }
        
        // Log original request for debugging (in development)
        if (process.env.NODE_ENV === 'development') {
          //console.log(`[SANITIZE] Processing ${req.method} ${req.path}`);
        }
        
        // Sanitize request body
        if (req.body && Object.keys(req.body).length > 0) {
          const originalBody = JSON.stringify(req.body);
          req.body = this.sanitizeRequestBody(req);
          
          // Check for significant content changes indicating potential XSS
          if (req.path.includes('/comments') && originalBody !== JSON.stringify(req.body)) {
            // Check if comment field was heavily modified
            const original = JSON.parse(originalBody);
            if (original.comment && InputSanitizer.containsXSS(original.comment)) {
              return res.status(400).json({
                error: 'Your comment could not be posted due to invalid content',
                code: 'INVALID_CONTENT'
              });
            }
          }
        }
        
        // Sanitize query parameters
        if (req.query && Object.keys(req.query).length > 0) {
          req.query = this.sanitizeQueryParams(req);
        }
        
        // Sanitize URL parameters
        if (req.params && Object.keys(req.params).length > 0) {
          req.params = this.sanitizeUrlParams(req);
        }
        
        next();
        
      } catch (error) {
        console.error('🚨 Sanitization middleware error:', error);
        
        // Log security incident
        AuditLogger.log({
          action: 'sanitization_error',
          resource: req.originalUrl,
          method: req.method,
          status: 'failure',
          user: req.user || null,
          ipAddress: req.ip || req.connection.remoteAddress,
          userAgent: req.headers['user-agent'],
          details: { error: error.message }
        });
        
        res.status(400).json({
          success: false,
          message: 'Invalid input data',
          code: 'SANITIZATION_ERROR'
        });
      }
    };
  }
  
  // Check if route should skip sanitization
  static shouldSkipSanitization(req) {
    const skipRoutes = [
      '/api/csrf/token',
      '/api/user/login',
      '/api/user/logout',
      '/api/user/verify-email',
      '/api/admin/audit-logs'
    ];
    
    const skipMethods = ['GET', 'HEAD', 'OPTIONS'];
    
    return skipRoutes.some(route => req.path.includes(route)) || 
           skipMethods.includes(req.method.toUpperCase());
  }
  
  // Sanitize request body based on route
  static sanitizeRequestBody(req) {
    const schema = this.getSchemaForRoute(req.path);
    
    if (schema) {
      // Use specific schema for known routes
      const sanitized = InputSanitizer.sanitizeObject(req.body, sanitizationSchemas[schema]);
      
      // Log if significant changes were made
      if (process.env.NODE_ENV === 'development') {
        this.logSanitizationChanges('body', req.body, sanitized, req);
      }
      
      return sanitized;
    } else {
      // Generic sanitization for unknown routes
      return this.genericSanitizeObject(req.body, req);
    }
  }
  
  // Sanitize query parameters
  static sanitizeQueryParams(req) {
    const sanitized = {};
    
    for (const [key, value] of Object.entries(req.query)) {
      // Common query parameters
      switch (key) {
        case 'page':
        case 'limit':
        case 'offset':
          sanitized[key] = InputSanitizer.sanitizeNumber(value, 1, 1000);
          break;
        case 'search':
        case 'query':
        case 'q':
          sanitized[key] = InputSanitizer.sanitizeText(value, 100);
          break;
        case 'category':
        case 'sort':
        case 'order':
          sanitized[key] = InputSanitizer.sanitizeText(value, 50);
          break;
        case 'email':
          sanitized[key] = InputSanitizer.sanitizeEmail(value);
          break;
        default:
          // Generic text sanitization
          sanitized[key] = InputSanitizer.sanitizeText(value, 200);
      }
    }
    
    return sanitized;
  }
  
  // Sanitize URL parameters
  static sanitizeUrlParams(req) {
    const sanitized = {};
    
    for (const [key, value] of Object.entries(req.params)) {
      // Check if it looks like an ObjectId
      if (key.includes('Id') || key === 'id') {
        sanitized[key] = InputSanitizer.sanitizeObjectId(value) || value;
      } else {
        sanitized[key] = InputSanitizer.sanitizeText(value, 100);
      }
    }
    
    return sanitized;
  }
  
  // Get sanitization schema for route
  static getSchemaForRoute(path) {
    for (const [route, schema] of Object.entries(routeSanitization)) {
      if (path.includes(route)) {
        return schema;
      }
    }
    return null;
  }
  
  // Generic object sanitization
  static genericSanitizeObject(obj, req) {
    if (!obj || typeof obj !== 'object') {
      return obj;
    }
    
    const sanitized = {};
    
    for (const [key, value] of Object.entries(obj)) {
      if (typeof value === 'string') {
        // Check for security violations
        if (InputSanitizer.containsXSS(value)) {
          InputSanitizer.logSecurityViolation('XSS_ATTEMPT', value, {
            userId: req.user?.userId,
            ip: req.ip,
            route: req.path
          });
          
          // Log security incident
          AuditLogger.log({
            action: 'xss_attempt_blocked',
            resource: req.originalUrl,
            method: req.method,
            status: 'blocked',
            user: req.user || null,
            ipAddress: req.ip || req.connection.remoteAddress,
            userAgent: req.headers['user-agent'],
            details: { field: key, value: value.substring(0, 100) }
          });
        }
        
        if (InputSanitizer.containsSQLInjection(value)) {
          InputSanitizer.logSecurityViolation('SQL_INJECTION_ATTEMPT', value, {
            userId: req.user?.userId,
            ip: req.ip,
            route: req.path
          });
          
          // Log security incident
          AuditLogger.log({
            action: 'sql_injection_attempt_blocked',
            resource: req.originalUrl,
            method: req.method,
            status: 'blocked',
            user: req.user || null,
            ipAddress: req.ip || req.connection.remoteAddress,
            userAgent: req.headers['user-agent'],
            details: { field: key, value: value.substring(0, 100) }
          });
        }
        
        // Sanitize based on field name patterns
        if (key.toLowerCase().includes('email')) {
          sanitized[key] = InputSanitizer.sanitizeEmail(value);
        } else if (key.toLowerCase().includes('url') || key.toLowerCase().includes('website')) {
          sanitized[key] = InputSanitizer.sanitizeUrl(value);
        } else if (key.toLowerCase().includes('username')) {
          sanitized[key] = InputSanitizer.sanitizeUsername(value);
        } else {
          sanitized[key] = InputSanitizer.sanitizeText(value, 1000);
        }
      } else if (typeof value === 'number') {
        sanitized[key] = InputSanitizer.sanitizeNumber(value);
      } else if (typeof value === 'boolean') {
        sanitized[key] = InputSanitizer.sanitizeBoolean(value);
      } else if (Array.isArray(value)) {
        sanitized[key] = value.map(item => 
          typeof item === 'string' ? InputSanitizer.sanitizeText(item, 200) : item
        );
      } else {
        sanitized[key] = value;
      }
    }
    
    return sanitized;
  }
  
  // Log sanitization changes for debugging
  static logSanitizationChanges(type, original, sanitized, req) {
    const changes = [];
    
    for (const [key, value] of Object.entries(original)) {
      if (sanitized[key] !== value && typeof value === 'string') {
        changes.push({
          field: key,
          original: value.length > 50 ? value.substring(0, 50) + '...' : value,
          sanitized: sanitized[key]?.length > 50 ? sanitized[key].substring(0, 50) + '...' : sanitized[key]
        });
      }
    }
    
    if (changes.length > 0) {
      //console.log(`🧹 [SANITIZE] Changes made to ${type} in ${req.path}:`, changes);
    }
  }
}

module.exports = SanitizationMiddleware;

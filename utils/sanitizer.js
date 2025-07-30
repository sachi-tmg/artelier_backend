// utils/sanitizer.js
const sanitizeHtml = require('sanitize-html');
const validator = require('validator');

// HTML sanitization configuration
const sanitizeConfig = {
  // Allow only safe HTML tags for rich text content
  allowedTags: ['b', 'i', 'em', 'strong', 'p', 'br'],
  allowedAttributes: {},
  allowedIframeHostnames: [],
  disallowedTagsMode: 'discard',
  allowedSchemes: [],
  allowedSchemesByTag: {},
  allowedSchemesAppliedToAttributes: [],
  allowProtocolRelative: false,
  enforceHtmlBoundary: true
};

// Strict configuration for user input (no HTML allowed)
const strictConfig = {
  allowedTags: [],
  allowedAttributes: {},
  disallowedTagsMode: 'discard',
  allowProtocolRelative: false,
  enforceHtmlBoundary: true
};

class InputSanitizer {
  
  // Sanitize text content (removes all HTML)
  static sanitizeText(input, maxLength = null) {
    if (!input || typeof input !== 'string') {
      return '';
    }
    
    // Remove all HTML tags and decode entities
    let sanitized = sanitizeHtml(input, strictConfig);
    
    // Trim whitespace
    sanitized = sanitized.trim();
    
    // Apply length limit if specified
    if (maxLength && sanitized.length > maxLength) {
      sanitized = sanitized.substring(0, maxLength);
    }
    
    return sanitized;
  }
  
  // Sanitize rich text content (allows safe HTML)
  static sanitizeRichText(input, maxLength = null) {
    if (!input || typeof input !== 'string') {
      return '';
    }
    
    let sanitized = sanitizeHtml(input, sanitizeConfig);
    sanitized = sanitized.trim();
    
    if (maxLength && sanitized.length > maxLength) {
      sanitized = sanitized.substring(0, maxLength);
    }
    
    return sanitized;
  }
  
  // Sanitize email
  static sanitizeEmail(email) {
    if (!email || typeof email !== 'string') {
      return '';
    }
    
    const sanitized = email.toLowerCase().trim();
    return validator.isEmail(sanitized) ? sanitized : '';
  }
  
  // Sanitize URL
  static sanitizeUrl(url) {
    if (!url || typeof url !== 'string') {
      return '';
    }
    
    const sanitized = url.trim();
    
    // Only allow HTTP/HTTPS URLs
    if (validator.isURL(sanitized, { 
      protocols: ['http', 'https'],
      require_protocol: true 
    })) {
      return sanitized;
    }
    
    return '';
  }
  
  // Sanitize username (alphanumeric + underscore/dash)
  static sanitizeUsername(username) {
    if (!username || typeof username !== 'string') {
      return '';
    }
    
    // Remove any non-alphanumeric characters except underscore and dash
    return username.replace(/[^a-zA-Z0-9_-]/g, '').trim().toLowerCase();
  }
  
  // Sanitize password (minimal sanitization to preserve security)
  static sanitizePassword(password) {
    if (!password || typeof password !== 'string') {
      return '';
    }
    
    // Only trim whitespace, don't modify the actual password content
    // Password validation should be done separately
    return password.trim();
  }
  
  // Sanitize date input
  static sanitizeDate(dateInput) {
    if (!dateInput) {
      return null;
    }
    
    const date = new Date(dateInput);
    return isNaN(date.getTime()) ? null : date;
  }
  
  // Sanitize filename
  static sanitizeFilename(filename) {
    if (!filename || typeof filename !== 'string') {
      return '';
    }
    
    // Remove path traversal attempts and dangerous characters
    return filename
      .replace(/[<>:"/\\|?*]/g, '') // Remove dangerous filename chars
      .replace(/\.\./g, '') // Remove path traversal
      .replace(/^\.+/, '') // Remove leading dots
      .trim();
  }
  
  // Sanitize MongoDB ObjectId
  static sanitizeObjectId(id) {
    if (!id || typeof id !== 'string') {
      return null;
    }
    
    return validator.isMongoId(id) ? id : null;
  }
  
  // Sanitize numeric input
  static sanitizeNumber(input, min = null, max = null) {
    if (input === null || input === undefined) {
      return null;
    }
    
    const num = parseFloat(input);
    if (isNaN(num)) {
      return null;
    }
    
    if (min !== null && num < min) {
      return min;
    }
    
    if (max !== null && num > max) {
      return max;
    }
    
    return num;
  }
  
  // Sanitize boolean input
  static sanitizeBoolean(input) {
    if (input === true || input === 'true' || input === 1 || input === '1') {
      return true;
    }
    return false;
  }
  
  // Generic object sanitizer
  static sanitizeObject(obj, schema) {
    if (!obj || typeof obj !== 'object') {
      return {};
    }
    
    const sanitized = {};
    
    for (const [key, config] of Object.entries(schema)) {
      if (obj.hasOwnProperty(key)) {
        const value = obj[key];
        
        switch (config.type) {
          case 'text':
            sanitized[key] = this.sanitizeText(value, config.maxLength);
            break;
          case 'richtext':
            sanitized[key] = this.sanitizeRichText(value, config.maxLength);
            break;
          case 'email':
            sanitized[key] = this.sanitizeEmail(value);
            break;
          case 'url':
            sanitized[key] = this.sanitizeUrl(value);
            break;
          case 'username':
            sanitized[key] = this.sanitizeUsername(value);
            break;
          case 'password':
            sanitized[key] = this.sanitizePassword(value);
            break;
          case 'date':
            sanitized[key] = this.sanitizeDate(value);
            break;
          case 'filename':
            sanitized[key] = this.sanitizeFilename(value);
            break;
          case 'objectid':
            sanitized[key] = this.sanitizeObjectId(value);
            break;
          case 'number':
            sanitized[key] = this.sanitizeNumber(value, config.min, config.max);
            break;
          case 'boolean':
            sanitized[key] = this.sanitizeBoolean(value);
            break;
          default:
            // If no type specified, treat as text
            sanitized[key] = this.sanitizeText(value, config.maxLength);
        }
      } else if (config.required) {
        // Set default value for required fields
        sanitized[key] = config.default || '';
      }
    }
    
    return sanitized;
  }
  
  // XSS detection
  static containsXSS(input) {
    if (!input || typeof input !== 'string') {
      return false;
    }
    
    const xssPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /javascript:/gi,
      /on\w+\s*=/gi,
      /<iframe/gi,
      /<object/gi,
      /<embed/gi,
      /<form/gi,
      /vbscript:/gi,
      /data:text\/html/gi
    ];
    
    return xssPatterns.some(pattern => pattern.test(input));
  }
  
  // SQL injection detection (for NoSQL context)
  static containsSQLInjection(input) {
    if (!input || typeof input !== 'string') {
      return false;
    }
    
    const sqlPatterns = [
      /(\$where|\$regex|\$gt|\$lt|\$ne|\$in|\$nin)/gi,
      /(union|select|insert|update|delete|drop|create|alter|exec|script)/gi,
      /['";].*(--)|(;)/gi
    ];
    
    return sqlPatterns.some(pattern => pattern.test(input));
  }
  
  // Log security violations
  static logSecurityViolation(violation, input, userInfo = {}) {
    console.warn(`🚨 SECURITY VIOLATION: ${violation}`, {
      input: input.substring(0, 100) + (input.length > 100 ? '...' : ''),
      userInfo,
      timestamp: new Date().toISOString()
    });
  }
}

module.exports = InputSanitizer;

const multer = require("multer");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs").promises;
const AuditLogger = require('../services/audit_logger');

const maxSize = 10 * 1024 * 1024; // 10MB for creation images

// Allowed MIME types for enhanced security
const ALLOWED_MIME_TYPES = [
  'image/jpeg',
  'image/jpg', 
  'image/png',
  'image/gif',
  'image/webp'
];

// Dangerous extensions to block
const BLOCKED_EXTENSIONS = [
  '.php', '.php3', '.php4', '.php5', '.phtml', '.pht',
  '.jsp', '.jspx', '.asp', '.aspx', '.ascx',
  '.exe', '.bat', '.cmd', '.com', '.scr', '.msi',
  '.js', '.vbs', '.vbe', '.ws', '.wsf', '.wsc',
  '.jar', '.war', '.ear', '.class',
  '.sh', '.bash', '.zsh', '.fish',
  '.py', '.rb', '.pl', '.cgi',
  '.htaccess', '.htpasswd',
  '.svg', '.html', '.htm', '.xml'
];

// File signature verification
const FILE_SIGNATURES = {
  'image/jpeg': [[0xFF, 0xD8, 0xFF]],
  'image/png': [[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]],
  'image/gif': [[0x47, 0x49, 0x46, 0x38, 0x37, 0x61], [0x47, 0x49, 0x46, 0x38, 0x39, 0x61]],
  'image/webp': [[0x52, 0x49, 0x46, 0x46]]
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "public/Creations");
  },
  filename: (req, file, cb) => {
    // Generate secure filename to prevent directory traversal
    const ext = path.extname(file.originalname).toLowerCase();
    const timestamp = Date.now();
    const randomBytes = crypto.randomBytes(8).toString('hex');
    cb(null, `CREATION-${timestamp}-${randomBytes}${ext}`);
  },
});

const imageFileFilter = (req, file, cb) => {
  try {
    // 1. Check MIME type
    if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
      logSecurityEvent(req, 'blocked', 'invalid_mime_type', {
        filename: file.originalname,
        mimetype: file.mimetype
      }).catch(console.error);
      return cb(new Error(`File type ${file.mimetype} not allowed. Only images are permitted.`), false);
    }

    // 2. Check file extension
    const ext = path.extname(file.originalname).toLowerCase();
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
    
    if (!allowedExtensions.includes(ext)) {
      logSecurityEvent(req, 'blocked', 'invalid_extension', {
        filename: file.originalname,
        extension: ext
      }).catch(console.error);
      return cb(new Error(`File extension ${ext} not allowed.`), false);
    }

    // 3. Check for dangerous extensions
    if (BLOCKED_EXTENSIONS.includes(ext)) {
      logSecurityEvent(req, 'blocked', 'dangerous_extension', {
        filename: file.originalname,
        extension: ext
      }).catch(console.error);
      return cb(new Error(`Dangerous file extension ${ext} blocked.`), false);
    }

    // 4. Check for double extensions and dangerous filename patterns
    const filename = file.originalname.toLowerCase();
    for (const blockedExt of BLOCKED_EXTENSIONS) {
      if (filename.includes(blockedExt)) {
        logSecurityEvent(req, 'blocked', 'suspicious_filename', {
          filename: file.originalname
        }).catch(console.error);
        return cb(new Error(`Suspicious filename detected.`), false);
      }
    }

    // 5. Check for path traversal and null bytes
    if (filename.includes('\x00') || filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
      logSecurityEvent(req, 'blocked', 'dangerous_characters', {
        filename: file.originalname
      }).catch(console.error);
      return cb(new Error(`Dangerous characters in filename.`), false);
    }

    cb(null, true);
  } catch (error) {
    console.error('Creation image upload filter error:', error);
    cb(new Error('File validation failed'), false);
  }
};

// Verify file signature after upload
const verifyFileSignature = async (filePath, expectedMimeType) => {
  try {
    const fileBuffer = await fs.readFile(filePath);
    const signatures = FILE_SIGNATURES[expectedMimeType];
    
    if (!signatures) return false;

    for (const signature of signatures) {
      const matches = signature.every((byte, index) => fileBuffer[index] === byte);
      if (matches) return true;
    }
    return false;
  } catch (error) {
    console.error('File signature verification error:', error);
    return false;
  }
};

// Security audit logging
const logSecurityEvent = async (req, action, reason, details) => {
  try {
    await AuditLogger.log({
      action: `creation_upload_${action}`,
      resource: req.originalUrl,
      method: req.method,
      status: action === 'blocked' ? 'failure' : 'success',
      user: req.user || null,
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.headers['user-agent'],
      details: { reason, uploadType: 'creation', ...details }
    });
  } catch (error) {
    console.error('Audit logging error:', error);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: imageFileFilter,
  limits: { 
    fileSize: maxSize,
    files: 1,
    fields: 10
  },
}).single("creationImage");

// Enhanced upload wrapper with proper error handling
const uploads = (req, res, next) => {
  upload(req, res, async (err) => {
    if (err) {
      // Handle different types of multer errors
      if (err instanceof multer.MulterError) {
        switch (err.code) {
          case 'LIMIT_FILE_SIZE':
            return res.status(400).json({
              success: false,
              message: 'File too large. Maximum size allowed is 10MB.',
              code: 'FILE_TOO_LARGE'
            });
          case 'LIMIT_FILE_COUNT':
            return res.status(400).json({
              success: false,
              message: 'Too many files. Only one file allowed.',
              code: 'TOO_MANY_FILES'
            });
          case 'LIMIT_UNEXPECTED_FILE':
            return res.status(400).json({
              success: false,
              message: 'Unexpected field name. Use "creationImage" as field name.',
              code: 'INVALID_FIELD'
            });
          default:
            return res.status(400).json({
              success: false,
              message: 'Upload error occurred.',
              code: 'UPLOAD_ERROR'
            });
        }
      } else {
        // Handle custom validation errors from imageFileFilter
        const message = err.message || 'Invalid file';
        let userMessage = message;
        let code = 'INVALID_FILE';

        if (message.includes('File type') && message.includes('not allowed')) {
          userMessage = 'Only image files are accepted. Please upload JPG, PNG, GIF, or WebP files.';
          code = 'INVALID_FILE_TYPE';
        } else if (message.includes('File extension') && message.includes('not allowed')) {
          userMessage = 'Invalid file extension. Only .jpg, .jpeg, .png, .gif, and .webp files are allowed.';
          code = 'INVALID_EXTENSION';
        } else if (message.includes('Dangerous file extension')) {
          userMessage = 'Security violation: This file type is not allowed for security reasons.';
          code = 'DANGEROUS_FILE';
        } else if (message.includes('Suspicious filename')) {
          userMessage = 'Invalid filename. Please rename your file and try again.';
          code = 'SUSPICIOUS_FILENAME';
        } else if (message.includes('Dangerous characters')) {
          userMessage = 'Invalid filename characters. Please use only letters, numbers, and basic symbols.';
          code = 'INVALID_FILENAME';
        }

        return res.status(400).json({
          success: false,
          message: userMessage,
          code: code
        });
      }
    }

    // If file upload successful, verify the file signature
    if (req.file) {
      try {
        const filePath = req.file.path;
        const mimeType = req.file.mimetype;

        // Verify file signature
        const isValidSignature = await verifyFileSignature(filePath, mimeType);
        
        if (!isValidSignature) {
          // Delete the malicious file
          await fs.unlink(filePath).catch(console.error);
          
          await logSecurityEvent(req, 'blocked', 'invalid_signature', {
            filename: req.file.originalname,
            mimetype: mimeType,
            savedPath: filePath
          });

          return res.status(400).json({
            success: false,
            message: 'Invalid image file. The file may be corrupted or not a genuine image.',
            code: 'INVALID_IMAGE'
          });
        }

        // Log successful upload
        await logSecurityEvent(req, 'success', 'valid_upload', {
          filename: req.file.originalname,
          savedAs: req.file.filename,
          mimetype: mimeType,
          size: req.file.size
        });
      } catch (error) {
        console.error('Creation upload verification error:', error);
        
        if (req.file && req.file.path) {
          await fs.unlink(req.file.path).catch(console.error);
        }

        return res.status(400).json({
          success: false,
          message: 'File verification failed. Please try uploading a different image.',
          code: 'VERIFICATION_ERROR'
        });
      }
    }

    next();
  });
};

module.exports = uploads;
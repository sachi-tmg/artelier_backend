// middleware/secure_upload.js - Enhanced file upload security
const multer = require("multer");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs").promises;
const AuditLogger = require('../services/audit_logger');

// Maximum file sizes
const MAX_PROFILE_SIZE = 2 * 1024 * 1024; // 2MB for profiles
const MAX_CREATION_SIZE = 10 * 1024 * 1024; // 10MB for creations
const MAX_COVER_SIZE = 5 * 1024 * 1024; // 5MB for covers

// Allowed MIME types (more secure than just extensions)
const ALLOWED_MIME_TYPES = [
  'image/jpeg',
  'image/jpg',
  'image/png',
  'image/gif',
  'image/webp'
];

// Dangerous extensions to explicitly block
const BLOCKED_EXTENSIONS = [
  '.php', '.php3', '.php4', '.php5', '.phtml', '.pht',
  '.jsp', '.jspx', '.asp', '.aspx', '.ascx',
  '.exe', '.bat', '.cmd', '.com', '.scr', '.msi',
  '.js', '.vbs', '.vbe', '.ws', '.wsf', '.wsc',
  '.jar', '.war', '.ear', '.class',
  '.sh', '.bash', '.zsh', '.fish',
  '.py', '.rb', '.pl', '.cgi',
  '.htaccess', '.htpasswd',
  '.svg', // SVG can contain JavaScript
  '.html', '.htm', '.xml'
];

// File signature verification (magic bytes)
const FILE_SIGNATURES = {
  'image/jpeg': [[0xFF, 0xD8, 0xFF]],
  'image/png': [[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]],
  'image/gif': [[0x47, 0x49, 0x46, 0x38, 0x37, 0x61], [0x47, 0x49, 0x46, 0x38, 0x39, 0x61]],
  'image/webp': [[0x52, 0x49, 0x46, 0x46]] // RIFF header
};

// Enhanced file filter
const createSecureFileFilter = (uploadType = 'general') => {
  return async (req, file, cb) => {
    try {
      // 1. Check MIME type
      if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
        await logSecurityEvent(req, 'file_upload_blocked', 'invalid_mime_type', {
          filename: file.originalname,
          mimetype: file.mimetype,
          uploadType
        });
        return cb(new Error(`File type ${file.mimetype} not allowed. Only images are permitted.`), false);
      }

      // 2. Check file extension (case-insensitive)
      const ext = path.extname(file.originalname).toLowerCase();
      const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
      
      if (!allowedExtensions.includes(ext)) {
        await logSecurityEvent(req, 'file_upload_blocked', 'invalid_extension', {
          filename: file.originalname,
          extension: ext,
          uploadType
        });
        return cb(new Error(`File extension ${ext} not allowed.`), false);
      }

      // 3. Check for dangerous extensions
      if (BLOCKED_EXTENSIONS.includes(ext)) {
        await logSecurityEvent(req, 'file_upload_blocked', 'dangerous_extension', {
          filename: file.originalname,
          extension: ext,
          uploadType
        });
        return cb(new Error(`Dangerous file extension ${ext} blocked.`), false);
      }

      // 4. Check for double extensions (e.g., image.php.jpg)
      const filename = file.originalname.toLowerCase();
      for (const blockedExt of BLOCKED_EXTENSIONS) {
        if (filename.includes(blockedExt)) {
          await logSecurityEvent(req, 'file_upload_blocked', 'double_extension', {
            filename: file.originalname,
            uploadType
          });
          return cb(new Error(`Suspicious filename detected: ${file.originalname}`), false);
        }
      }

      // 5. Check filename for null bytes and other dangerous characters
      if (filename.includes('\x00') || filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
        await logSecurityEvent(req, 'file_upload_blocked', 'dangerous_filename', {
          filename: file.originalname,
          uploadType
        });
        return cb(new Error(`Dangerous characters in filename.`), false);
      }

      cb(null, true);
    } catch (error) {
      console.error('File filter error:', error);
      cb(new Error('File validation failed'), false);
    }
  };
};

// Verify file signature after upload
const verifyFileSignature = async (filePath, expectedMimeType) => {
  try {
    const fileBuffer = await fs.readFile(filePath);
    const signatures = FILE_SIGNATURES[expectedMimeType];
    
    if (!signatures) {
      return false;
    }

    // Check if file starts with any of the expected signatures
    for (const signature of signatures) {
      const matches = signature.every((byte, index) => fileBuffer[index] === byte);
      if (matches) {
        return true;
      }
    }

    return false;
  } catch (error) {
    console.error('File signature verification error:', error);
    return false;
  }
};

// Generate secure filename
const generateSecureFilename = (originalname, uploadType) => {
  const ext = path.extname(originalname).toLowerCase();
  const timestamp = Date.now();
  const randomBytes = crypto.randomBytes(8).toString('hex');
  const prefix = uploadType.toUpperCase();
  
  return `${prefix}-${timestamp}-${randomBytes}${ext}`;
};

// Enhanced storage configuration
const createSecureStorage = (destination, uploadType) => {
  return multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, destination);
    },
    filename: (req, file, cb) => {
      const secureFilename = generateSecureFilename(file.originalname, uploadType);
      cb(null, secureFilename);
    }
  });
};

// Post-upload security verification middleware
const postUploadVerification = (uploadType) => {
  return async (req, res, next) => {
    if (!req.file) {
      return next();
    }

    try {
      const filePath = req.file.path;
      const mimeType = req.file.mimetype;

      // Verify file signature
      const isValidSignature = await verifyFileSignature(filePath, mimeType);
      
      if (!isValidSignature) {
        // Delete the malicious file
        await fs.unlink(filePath).catch(console.error);
        
        await logSecurityEvent(req, 'file_upload_blocked', 'invalid_signature', {
          filename: req.file.originalname,
          mimetype: mimeType,
          uploadType,
          savedPath: filePath
        });

        return res.status(400).json({
          success: false,
          message: 'File signature verification failed. The file may be corrupted or not a valid image.',
          code: 'INVALID_FILE_SIGNATURE'
        });
      }

      // Log successful upload
      await logSecurityEvent(req, 'file_upload_success', 'valid_upload', {
        filename: req.file.originalname,
        savedAs: req.file.filename,
        mimetype: mimeType,
        size: req.file.size,
        uploadType
      });

      next();
    } catch (error) {
      console.error('Post-upload verification error:', error);
      
      // Delete file on error
      if (req.file && req.file.path) {
        await fs.unlink(req.file.path).catch(console.error);
      }

      return res.status(500).json({
        success: false,
        message: 'File verification failed',
        code: 'VERIFICATION_ERROR'
      });
    }
  };
};

// Audit logging helper
const logSecurityEvent = async (req, action, reason, details) => {
  try {
    await AuditLogger.log({
      action: `file_upload_${action}`,
      resource: req.originalUrl,
      method: req.method,
      status: action.includes('blocked') ? 'failure' : 'success',
      user: req.user || null,
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.headers['user-agent'],
      details: { reason, ...details }
    });
  } catch (error) {
    console.error('Audit logging error:', error);
  }
};

// Create secure upload middleware for different types
const createSecureUpload = (uploadType, destination, maxSize) => {
  const storage = createSecureStorage(destination, uploadType);
  const fileFilter = createSecureFileFilter(uploadType);
  
  return {
    upload: multer({
      storage,
      fileFilter,
      limits: { 
        fileSize: maxSize,
        files: 1,
        fields: 10
      }
    }).single(getFieldName(uploadType)),
    verification: postUploadVerification(uploadType)
  };
};

const getFieldName = (uploadType) => {
  switch (uploadType) {
    case 'profile': return 'profilePicture';
    case 'cover': return 'coverPicture';
    case 'creation': return 'creationImage';
    default: return 'image';
  }
};

// Export secure upload configurations
const secureProfileUpload = createSecureUpload('profile', 'public/Profiles', MAX_PROFILE_SIZE);
const secureCoverUpload = createSecureUpload('cover', 'public/Covers', MAX_COVER_SIZE);
const secureCreationUpload = createSecureUpload('creation', 'public/Creations', MAX_CREATION_SIZE);

module.exports = {
  secureProfileUpload,
  secureCoverUpload,
  secureCreationUpload,
  verifyFileSignature,
  generateSecureFilename,
  ALLOWED_MIME_TYPES,
  BLOCKED_EXTENSIONS
};

const AuditLogger = require('../services/audit_logger');

// Store failed attempt counters (in production, use Redis)
const attemptCounters = new Map();

// Cleanup old counters every hour
setInterval(() => {
  const now = Date.now();
  const oneHour = 60 * 60 * 1000;
  
  for (const [key, data] of attemptCounters.entries()) {
    if (now - data.lastAttempt > oneHour) {
      attemptCounters.delete(key);
    }
  }
}, 60 * 60 * 1000);

// Risk assessment middleware
const assessRisk = (options = {}) => {
  const {
    maxAttempts = 3,
    timeWindow = 15 * 60 * 1000, // 15 minutes
    action = 'login'
  } = options;

  return async (req, res, next) => {
    try {
      const identifier = req.ip || req.connection.remoteAddress;
      const now = Date.now();
      
      // Get current attempt data
      let attemptData = attemptCounters.get(identifier) || {
        count: 0,
        lastAttempt: now,
        action: action
      };

      // Reset counter if time window has passed
      if (now - attemptData.lastAttempt > timeWindow) {
        attemptData = {
          count: 0,
          lastAttempt: now,
          action: action
        };
      }

      // Check if CAPTCHA is required based on previous failures
      const captchaRequired = attemptData.count >= maxAttempts;
      
      // Add risk assessment to request
      req.riskAssessment = {
        captchaRequired,
        attemptCount: attemptData.count,
        riskLevel: getRiskLevel(attemptData.count, maxAttempts),
        action: action
      };

      if (captchaRequired) {
        await AuditLogger.log({
          action: 'captcha_required_by_risk',
          resource: req.originalUrl,
          method: req.method,
          status: 'info',
          user: req.user || null,
          ipAddress: identifier,
          userAgent: req.headers['user-agent'],
          details: {
            attemptCount: attemptData.count,
            riskLevel: req.riskAssessment.riskLevel,
            action: action
          }
        });
      }

      next();

    } catch (error) {
      console.error('Risk assessment error:', error);
      // Don't block the request if risk assessment fails
      req.riskAssessment = {
        captchaRequired: false,
        attemptCount: 0,
        riskLevel: 'low',
        action: action
      };
      next();
    }
  };
};

// Record failed attempt
const recordFailedAttempt = (action = 'login') => {
  return async (req, res, next) => {
    try {
      const identifier = req.ip || req.connection.remoteAddress;
      const now = Date.now();
      
      // Get current attempt data
      let attemptData = attemptCounters.get(identifier) || {
        count: 0,
        lastAttempt: now,
        action: action
      };

      // Increment counter
      attemptData.count++;
      attemptData.lastAttempt = now;
      attemptData.action = action;

      // Store updated data
      attemptCounters.set(identifier, attemptData);

      await AuditLogger.log({
        action: 'failed_attempt_recorded',
        resource: req.originalUrl,
        method: req.method,
        status: 'info',
        user: req.user || null,
        ipAddress: identifier,
        userAgent: req.headers['user-agent'],
        details: {
          attemptCount: attemptData.count,
          riskLevel: getRiskLevel(attemptData.count, 3),
          action: action
        }
      });

      next();

    } catch (error) {
      console.error('Failed attempt recording error:', error);
      next();
    }
  };
};

// Clear failed attempts on successful action
const clearFailedAttempts = (action = 'login') => {
  return async (req, res, next) => {
    try {
      const identifier = req.ip || req.connection.remoteAddress;
      
      if (attemptCounters.has(identifier)) {
        const attemptData = attemptCounters.get(identifier);
        
        if (attemptData.action === action) {
          attemptCounters.delete(identifier);
          
          await AuditLogger.log({
            action: 'failed_attempts_cleared',
            resource: req.originalUrl,
            method: req.method,
            status: 'success',
            user: req.user || null,
            ipAddress: identifier,
            userAgent: req.headers['user-agent'],
            details: {
              clearedAttempts: attemptData.count,
              action: action
            }
          });
        }
      }

      next();

    } catch (error) {
      console.error('Failed attempt clearing error:', error);
      next();
    }
  };
};

// Conditional CAPTCHA verification based on risk
const conditionalCaptcha = (options = {}) => {
  const {
    maxAttempts = 3,
    timeWindow = 15 * 60 * 1000,
    action = 'login'
  } = options;

  return async (req, res, next) => {
    try {
      // First assess risk
      await new Promise((resolve, reject) => {
        assessRisk({ maxAttempts, timeWindow, action })(req, res, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });

      // If CAPTCHA is required by risk assessment, verify it
      if (req.riskAssessment?.captchaRequired) {
        const { captchaToken, captchaText } = req.body;
        
        if (!captchaToken || !captchaText) {
          return res.status(400).json({
            success: false,
            message: 'CAPTCHA verification required due to multiple failed attempts',
            code: 'CAPTCHA_REQUIRED_BY_RISK',
            riskLevel: req.riskAssessment.riskLevel,
            attemptCount: req.riskAssessment.attemptCount
          });
        }

        // Use the existing CAPTCHA verification logic
        const { verifyCaptcha } = require('./captcha_middleware');
        return verifyCaptcha(req, res, next);
      }

      // No CAPTCHA required, proceed
      next();

    } catch (error) {
      console.error('Conditional CAPTCHA error:', error);
      res.status(500).json({
        success: false,
        message: 'Security verification failed',
        code: 'SECURITY_ERROR'
      });
    }
  };
};

// Get risk level description
const getRiskLevel = (attemptCount, maxAttempts) => {
  if (attemptCount === 0) return 'none';
  if (attemptCount < maxAttempts / 2) return 'low';
  if (attemptCount < maxAttempts) return 'medium';
  return 'high';
};

// Get risk statistics (for admin)
const getRiskStats = async (req, res) => {
  try {
    const stats = {
      totalTrackedIPs: attemptCounters.size,
      highRiskIPs: 0,
      mediumRiskIPs: 0,
      lowRiskIPs: 0,
      totalFailedAttempts: 0,
      topFailureIPs: []
    };

    const ipStats = [];
    
    for (const [ip, data] of attemptCounters.entries()) {
      stats.totalFailedAttempts += data.count;
      
      const riskLevel = getRiskLevel(data.count, 3);
      switch (riskLevel) {
        case 'high':
          stats.highRiskIPs++;
          break;
        case 'medium':
          stats.mediumRiskIPs++;
          break;
        case 'low':
          stats.lowRiskIPs++;
          break;
      }

      ipStats.push({
        ip: ip.replace(/\d+/g, 'XXX'), // Mask IP for privacy
        count: data.count,
        riskLevel: riskLevel,
        lastAttempt: new Date(data.lastAttempt).toISOString(),
        action: data.action
      });
    }

    // Get top 10 failure IPs
    stats.topFailureIPs = ipStats
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    res.status(200).json({
      success: true,
      stats
    });

  } catch (error) {
    console.error('Risk stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get risk statistics'
    });
  }
};

module.exports = {
  assessRisk,
  recordFailedAttempt,
  clearFailedAttempts,
  conditionalCaptcha,
  getRiskStats
};

const { recordFailedAttempt, clearFailedAttempts } = require('../middleware/risk_assessment');

// Wrapper to track login success/failure for risk assessment
const trackLoginResult = (controllerFunction) => {
  return async (req, res, next) => {
    // Store original res.json to intercept response
    const originalJson = res.json;
    let responseIntercepted = false;

    res.json = function(data) {
      if (!responseIntercepted) {
        responseIntercepted = true;
        
        // Check if login was successful
        const isSuccess = data.success === true || (data.mfaRequired === true && data.tempToken);
        const isFailure = data.success === false && res.statusCode >= 400;

        if (isSuccess) {
          // Clear failed attempts on successful login
          clearFailedAttempts('login')(req, res, () => {});
        } else if (isFailure) {
          // Record failed attempt
          recordFailedAttempt('login')(req, res, () => {});
        }
      }
      
      // Call original json method
      return originalJson.call(this, data);
    };

    // Call the original controller function
    return controllerFunction(req, res, next);
  };
};

// Wrapper for registration tracking
const trackRegistrationResult = (controllerFunction) => {
  return async (req, res, next) => {
    const originalJson = res.json;
    let responseIntercepted = false;

    res.json = function(data) {
      if (!responseIntercepted) {
        responseIntercepted = true;
        
        const isSuccess = data.success === true;
        const isFailure = data.success === false && res.statusCode >= 400;

        if (isSuccess) {
          clearFailedAttempts('registration')(req, res, () => {});
        } else if (isFailure) {
          recordFailedAttempt('registration')(req, res, () => {});
        }
      }
      
      return originalJson.call(this, data);
    };

    return controllerFunction(req, res, next);
  };
};

// Wrapper for password reset tracking
const trackPasswordResetResult = (controllerFunction) => {
  return async (req, res, next) => {
    const originalJson = res.json;
    let responseIntercepted = false;

    res.json = function(data) {
      if (!responseIntercepted) {
        responseIntercepted = true;
        
        const isSuccess = data.success === true;
        const isFailure = data.success === false && res.statusCode >= 400;

        if (isSuccess) {
          clearFailedAttempts('password_reset')(req, res, () => {});
        } else if (isFailure) {
          recordFailedAttempt('password_reset')(req, res, () => {});
        }
      }
      
      return originalJson.call(this, data);
    };

    return controllerFunction(req, res, next);
  };
};

module.exports = {
  trackLoginResult,
  trackRegistrationResult,
  trackPasswordResetResult
};

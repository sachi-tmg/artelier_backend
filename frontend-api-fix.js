import axios from "axios";

// CSRF token management
let csrfToken = null;

// Function to get CSRF token
const getCSRFToken = async () => {
  if (csrfToken) return csrfToken;
  
  try {
    // Fixed: Use correct backend URL (port 3000 is likely your backend)
    const response = await axios.get('https://localhost:3000/api/csrf/token', {
      withCredentials: true
    });
    
    if (response.data.success) {
      csrfToken = response.data.csrfToken;
      return csrfToken;
    }
  } catch (error) {
    console.error('Failed to get CSRF token:', error);
  }
  return null;
};

// Clear CSRF token (for logout)
export const clearCSRFToken = () => {
  csrfToken = null;
};

// Force refresh CSRF token
export const refreshCSRFToken = async () => {
  csrfToken = null;
  return await getCSRFToken();
};

const api = axios.create({
  // Fixed: Use correct backend URL - your backend runs on port 3000
  baseURL: "https://localhost:3000",
  withCredentials: true,
  headers: {
    "Content-Type": "application/json",
  },
});

// Request interceptor to add CSRF token
api.interceptors.request.use(
  async (config) => {
    // Skip CSRF for password strength check (it's a read-only operation)
    const skipCSRF = [
      '/api/user/check-password-strength',
      '/api/csrf/token'
    ];
    
    // Add CSRF token for state-changing methods (excluding password strength check)
    if (['post', 'put', 'patch', 'delete'].includes(config.method.toLowerCase()) && 
        !skipCSRF.some(path => config.url.includes(path))) {
      const token = await getCSRFToken();
      if (token) {
        config.headers['x-csrf-token'] = token;
      }
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle CSRF errors
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 403 && 
        error.response?.data?.code?.includes('CSRF')) {
      
      console.log('CSRF token invalid, refreshing...');
      csrfToken = null; // Clear invalid token
      
      // Try to get new token and retry request
      const newToken = await getCSRFToken();
      if (newToken && error.config) {
        error.config.headers['x-csrf-token'] = newToken;
        return api.request(error.config);
      }
    }
    return Promise.reject(error);
  }
);

// Rest of your API functions remain the same...
export const registerUser = (data) => {
  return api.post("/api/user/registerUser", data);
};

export const loginUser = (data) => {
  if (data.tempToken && data.code) {
    return api.post("/api/user/verify-mfa", data);
  }
  return api.post("/api/user/login", data);
};

export const logoutUser = () => {
  clearCSRFToken();
  return api.post("/api/user/logout");
};

export const verifyEmail = ({ token, email }) =>
  api.get("/api/user/verify-email", {
    params: { token, email },
  });

export const resendVerificationEmail = (email) =>
  api.post("/api/user/resend-verification", { email });

export const sendSignupOtp = (email) => {
  return api.post("/api/user/send-signup-otp", { email });
};

export const verifySignupOtp = (data) => {
  return api.post("/api/user/verify-signup-otp", data);
};

export const getProfileInfo = (data) => {
  return api.post("/api/user/profile", data);
};

export const getCurrentUser = () => {
  return api.get("/api/user/me");
};

// User Management
export const adminGetUsers = (params = {}) => {
  return api.get("/api/admin/users", { params });
};

export const adminGetUserDetails = (userId) => {
  return api.get(`/api/admin/users/${userId}`);
};

export const adminUpdateUser = (userId, updates) => {
  return api.put(`/api/admin/users/${userId}`, updates);
};

export const adminDeleteUser = (userId) => {
  return api.delete(`/api/admin/users/${userId}`);
};

export const adminUnlockUser = (userId) => {
  return api.post(`/api/admin/users/${userId}/unlock`);
};

// Dashboard
export const adminGetDashboardStats = () => {
  return api.get("/api/admin/dashboard/stats");
};

// Order Management
export const adminGetOrders = (params = {}) => {
  return api.get("/api/admin/orders", { params });
};

export const adminUpdateOrderStatus = (orderId, statusData) => {
  return api.put(`/api/admin/orders/${orderId}`, statusData);
};

export const adminGetOrderDetails = (orderId) => {
  return api.get(`/api/admin/orders/${orderId}`);
};

// Audit Logs
export const adminGetAuditLogs = (params = {}) => {
  return api.get("/api/admin/audit-logs", { params });
};

export const adminGetSecurityAlerts = () => {
  return api.get("/api/admin/security-alerts");
};

export const adminGetAuditStats = () => {
  return api.get("/api/admin/audit-stats");
};

// Admin Management
export const createAdminUser = (userData) => {
  return api.post("/api/admin/users", userData);
};

// User profile
export const updateUserProfile = (data) => 
  api.put("/api/user/update-profile", data);

export const updateUserPassword = (currentPassword, newPassword) => 
  api.put("/api/user/update-password", { currentPassword, newPassword });

// Password security functions
export const checkPasswordStatus = () => 
  api.get("/api/user/password-status");

// Fixed: This function should work now with proper CSRF handling
export const checkPasswordStrength = (password) => 
  api.post("/api/user/check-password-strength", { password });

export const forcePasswordChange = (userId) => 
  api.post("/api/admin/force-password-change", { userId });

export const updateUserNotifications = (settings) => 
  api.put("/api/user/update-notifications", settings);

export const deleteUserAccount = () => 
  api.delete("/api/user/delete-account");

export const uploadProfilePicture = (formData) =>
  api.post("/api/user/upload-profile-picture", formData, {
    headers: {
      "Content-Type": "multipart/form-data",
    },
  });

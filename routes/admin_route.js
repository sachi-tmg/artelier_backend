// routes/adminRoutes.js
const express = require('express');
const router = express.Router();
const adminController = require('../controllers/admin_controller');
const { requireAdmin } = require('../middleware/auth_middleware');

// User management
router.get('/users', requireAdmin, adminController.listAllUsers);
router.get('/users/:userId', requireAdmin, adminController.getUserDetails);
router.put('/users/:userId', requireAdmin, adminController.updateUser);
router.delete('/users/:userId', requireAdmin, adminController.deleteUser);
router.post('/users/:userId/unlock', requireAdmin, adminController.unlockUserAccount);

// Dashboard
router.get('/dashboard/stats', requireAdmin, adminController.getDashboardStats);

module.exports = router;
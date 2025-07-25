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

// Order management
router.get('/orders/stats', requireAdmin, adminController.getOrderStats);
router.get('/orders', requireAdmin, adminController.listAllOrders);
router.get('/orders/:orderId', requireAdmin, adminController.getOrderDetails);
router.put('/orders/:orderId', requireAdmin, adminController.updateOrderStatus);
router.delete('/orders/:orderId', requireAdmin, adminController.deleteOrder);

// Dashboard
router.get('/dashboard/stats', requireAdmin, adminController.getDashboardStats);

module.exports = router;
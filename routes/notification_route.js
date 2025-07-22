const express = require('express');
const router = express.Router();
const { 
    notificationsAvailability,
    getNotifications,
    notificationCount
} = require('../controllers/notification_controller');
const { verifyJWT } = require('../controllers/creation_controller');

router.get('/availability', verifyJWT, notificationsAvailability);
router.post('/', verifyJWT, getNotifications);
router.post('/count', verifyJWT, notificationCount);

module.exports = router;
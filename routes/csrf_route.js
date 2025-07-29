// routes/csrf_route.js
const express = require('express');
const router = express.Router();
const { getCSRFToken } = require('../middleware/csrf_protection');

// Route to get CSRF token
router.get('/token', getCSRFToken);

module.exports = router;

// routes/favorite_routes.js
const express = require('express');
const router = express.Router();
const { verifyJWT } = require('../controllers/creation_controller'); // Reuse your JWT middleware
const favoriteController = require('../controllers/favorite_controller');

// Toggle favorite status for a creation
router.post('/toggle', verifyJWT, favoriteController.toggleFavorite);

// Get all favorites for the authenticated user
router.get('/', verifyJWT, favoriteController.getFavorites);

// Check if a specific creation is favorited by the user
router.get('/status/:creationId', verifyJWT, favoriteController.checkFavoriteStatus);

module.exports = router;
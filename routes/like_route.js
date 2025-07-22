const express = require('express');
const router = express.Router();
const { verifyJWT } = require('../controllers/creation_controller');
const { toggleLike, checkLikeStatus } = require('../controllers/like_controller');

router.post('/likes', verifyJWT, (req, res, next) => {
  console.log('[SERVER DEBUG] /api/likes route hit', {
    method: req.method,
    body: req.body,
    headers: req.headers
  });
  next();
}, toggleLike);

// In your like routes file
router.get('/status/:creationId', verifyJWT, checkLikeStatus);

module.exports = router;
const express = require('express');
const router = express.Router();
const { verifyJWT } = require('../controllers/creation_controller');
const commentController = require('../controllers/comment_controller');

router.get('/:creationId', commentController.getComments);
router.post('/', verifyJWT, commentController.postComment);
router.post('/:commentId/like', verifyJWT, commentController.toggleCommentLike);
router.get('/:commentId/like-status', verifyJWT, commentController.checkCommentLikeStatus);

module.exports = router;
const Comment = require('../models/comment');
const Creation = require('../models/creation');
const Notification = require('../models/notification');
const AuditLogger = require('../services/audit_logger');

exports.getComments = async (req, res) => {
    try {
        const { creationId } = req.params;
        const creation = await Creation.findOne({ creation_id: creationId });

        if (!creation) {
            return res.status(404).json({ error: "Creation not found" });
        }

        const comments = await Comment.find({ 
            creation_id: creation._id,
            isReply: false 
        })
        .populate('commented_by', 'username profilePicture fullName')
        .populate({
            path: 'children',
            populate: {
                path: 'commented_by',
                select: 'username profilePicture fullName'
            }
        })
        .sort({ dateCommented: -1 });

        res.status(200).json(comments);
    } catch (error) {
        console.error('Error fetching comments:', error);
        res.status(500).json({ error: error.message });
    }
};

exports.postComment = async (req, res) => {
    try {
        const { creationId, comment, parentId } = req.body;
        const userId = req.user.userId;

        if (!creationId || !comment) {
            return res.status(400).json({ error: "Creation ID and comment text are required" });
        }

        const creation = await Creation.findOne({ creation_id: creationId });
        if (!creation) {
            return res.status(404).json({ error: "Creation not found" });
        }

        const isReply = !!parentId;
        const newComment = new Comment({
            creation_id: creation._id,
            creation_author: creation.userId,
            comment,
            commented_by: userId,
            isReply,
            parent: isReply ? parentId : null
        });

        await newComment.save();

        if (isReply) {
            await Comment.findByIdAndUpdate(parentId, {
                $push: { children: newComment._id }
            });
        }

        await Creation.findByIdAndUpdate(creation._id, {
            $inc: { 'activity.commentCount': 1 }
        });

        if (userId !== creation.userId.toString()) {
            const notification = new Notification({
                type: isReply ? "comment_reply" : "comment",
                creation: creation._id,
                notification_for: creation.userId,
                user: userId,
                comment: newComment._id
            });
            await notification.save();
        }

        // Log comment posting
        await AuditLogger.log({
          action: 'comment_posted',
          resource: '/api/comment',
          method: 'POST',
          status: 'success',
          user: { _id: userId, username: req.user.username, role: req.user.role },
          ipAddress: req.ip || req.connection.remoteAddress,
          userAgent: req.headers['user-agent'],
          details: { 
            creationId: creationId,
            commentType: isReply ? 'reply' : 'comment',
            commentTime: new Date()
          }
        });

        res.status(201).json(newComment);
    } catch (error) {
        console.error('Error creating comment:', error);
        res.status(500).json({ error: error.message });
    }
};

exports.toggleCommentLike = async (req, res) => {
  try {
    const userId = req.user.userId;
    const { commentId } = req.params;

    if (!commentId) {
      return res.status(400).json({ error: "Comment ID is required" });
    }

    const comment = await Comment.findById(commentId);
    if (!comment) {
      return res.status(404).json({ error: "Comment not found" });
    }

    const isLiked = comment.liked_by.includes(userId);
    let updatedComment;

    if (isLiked) {
      // Unlike the comment
      updatedComment = await Comment.findByIdAndUpdate(
        commentId,
        { 
          $inc: { likes: -1 },
          $pull: { liked_by: userId }
        },
        { new: true }
      );

      // Remove notification if exists
      await Notification.findOneAndDelete({
        user: userId,
        type: "comment_like",
        comment: commentId
      });
    } else {
      // Like the comment
      updatedComment = await Comment.findByIdAndUpdate(
        commentId,
        { 
          $inc: { likes: 1 },
          $push: { liked_by: userId }
        },
        { new: true }
      );

      // Create notification if not the comment author
      if (userId !== comment.commented_by.toString()) {
        const notification = new Notification({
          type: "comment_like",
          comment: commentId,
          notification_for: comment.commented_by,
          user: userId
        });
        await notification.save();
      }
    }

    res.status(200).json({ 
      success: true,
      likedByUser: !isLiked,
      likeCount: updatedComment.likes,
      liked_by: updatedComment.liked_by
    });
  } catch (error) {
    console.error('Error toggling comment like:', error);
    res.status(500).json({ error: error.message });
  }
};

exports.checkCommentLikeStatus = async (req, res) => {
  try {
    const userId = req.user.userId;
    const { commentId } = req.params;

    const comment = await Comment.findById(commentId);
    if (!comment) {
      return res.status(404).json({ error: "Comment not found" });
    }

    const isLiked = comment.liked_by.some(id => id.toString() === userId.toString());

    res.status(200).json({ 
      isLiked,
      likeCount: comment.likes
    });
  } catch (error) {
    console.error('Error checking comment like status:', error);
    res.status(500).json({ error: error.message });
  }
};
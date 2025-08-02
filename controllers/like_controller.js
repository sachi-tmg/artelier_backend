const Creation = require('../models/creation');
const Notification = require('../models/notification');
const User = require('../models/user');

exports.toggleLike = async (req, res) => {
  try {
    const userId = req.user.userId;
    const { creationId } = req.body;

    // //console.log('[CONTROLLER DEBUG] toggleLike started', {
    //   userId,
    //   creationId
    // });

    if (!creationId) {
      return res.status(400).json({ error: "Creation ID is required" });
    }

    // CHANGE HERE: Find by creation_id instead of _id
    const creation = await Creation.findOne({ creation_id: creationId });
    
    // //console.log('[CONTROLLER DEBUG] Found creation:', creation ? creation.creation_id : 'null');
    
    if (!creation) {
      return res.status(404).json({ error: "Creation not found" });
    }

    const existingNotification = await Notification.findOne({
      user: userId,
      type: "like",
      creation: creation._id // Use internal _id for relationships
    });

    const isLiked = !!existingNotification;
    let incrementVal = isLiked ? -1 : 1;

    // CHANGE HERE: Update by creation_id
    const updatedCreation = await Creation.findOneAndUpdate(
      { creation_id: creationId },
      { $inc: { "activity.likeCount": incrementVal } },
      { new: true }
    );

    // Update total_likes in the creator's profile
    await User.findByIdAndUpdate(
      creation.userId, // assuming this field holds the owner's user ID
      { $inc: { "account_info.total_likes": incrementVal } }
    );

    if (!existingNotification) {
      const notification = new Notification({
          type: "like",
          creation: creation._id,
          notification_for: creation.userId,
          user: userId
        });
      await notification.save();
      
      return res.status(200).json({ 
        success: true,
        likedByUser: true,
        likeCount: updatedCreation.activity.likeCount
      });
    } else {
      // Remove the like notification when unliking
      await Notification.findByIdAndDelete(existingNotification._id);
      
      return res.status(200).json({ 
        success: true,
        likedByUser: false,
        likeCount: updatedCreation.activity.likeCount
      });
    }
  } catch (error) {
    console.error('[CONTROLLER DEBUG] Error in toggleLike:', error);
    return res.status(500).json({ error: error.message });
  }
};

exports.checkLikeStatus = async (req, res) => {
  try {
    const userId = req.user.userId;
    const { creationId } = req.params;

    // //console.log('[DEBUG] Checking like status for:', {
    //   userId,
    //   creationId
    // });

    // Find the creation first to get its MongoDB _id
    const creation = await Creation.findOne({ creation_id: creationId });
    if (!creation) {
      return res.status(404).json({ error: "Creation not found" });
    }

    // Check if notification exists (user already liked)
    const existingNotification = await Notification.findOne({
      user: userId,
      type: "like",
      creation: creation._id
    });

    res.status(200).json({ 
      isLiked: !!existingNotification,
      likeCount: creation.activity.likeCount
    });
  } catch (error) {
    console.error('[ERROR] checkLikeStatus failed:', error);
    res.status(500).json({ error: error.message });
  }
};
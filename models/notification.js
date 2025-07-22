const mongoose = require("mongoose");

const notificationSchema = mongoose.Schema({
    type: {
        type: String,
        enum: ['like', 'comment', 'follow', 'purchase', 'comment_reply','comment_like'],
        required: true
    },
    creation: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'creations',
        required: function() {
            return this.type === 'like' || this.type === 'comment' || this.type === 'favorite';
        }
    },
    notification_for: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'users',
        required: true
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'users',
        required: true
    },
    comment: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'comments'
    },
    order: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Order',
        required: function() {
            return this.type === 'purchase';
        }
    },
    seen: {
        type: Boolean,
        default: false
    }
}, {
    timestamps: true
});

const Notification = mongoose.model("Notification", notificationSchema);

module.exports = Notification;
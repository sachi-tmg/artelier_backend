const mongoose = require("mongoose");

const commentSchema = new mongoose.Schema({
    creation_id: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'creations' 
    },
    creation_author: {
        type: mongoose.Schema.Types.ObjectId,
        required: true, 
        ref: 'users',
    },
    comment: {
        type: String,
        required: true,
        trim: true,
        maxlength: 500
    },
    children: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'comments'
    }],
    commented_by: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'users'
    },
    isReply: {
        type: Boolean,
        default: false,
    },
    parent: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'comments',
        default: null
    },
    likes: {
        type: Number,
        default: 0
    },
    liked_by: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'users'
    }],
    dateCommented: {
        type: Date,
        default: Date.now,
    },
    dateUpdated: {
        type: Date,
        default: Date.now,
    },
});

commentSchema.pre('save', function(next) {
    this.dateUpdated = Date.now();
    next();
});

const Comment = mongoose.model("comments", commentSchema);
module.exports = Comment;
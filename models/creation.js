const mongoose = require("mongoose");

const creationSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "users",
        required: true,
    },
    creation_id: {
        type: String,
        required: true,
        unique: true,
    },
    title: {
        type: String,
        required: true,
        index: true 
    },
    des: {
        type: String,
        maxlength: 500,
        // required: true
    },
    category: {
        type: String,
        required: true,
        index: true 
    },
    materials: {
        type: String,
        required: true,
        index: true 
    },
    creationPicture: {
        type: String,
        default: null,
    },
    dimension: {
        type: String,
        required: false,
    },
    forSale: {
        type: Boolean,
        required: true,
        default: false,
    },
    price: {
        type: String,
        required: false,
        default: '0',
    },
    dateCreated: {
        type: Date,
        default: Date.now,
    },
    dateUpdated: {
        type: Date,
        default: Date.now,
    },
    activity: {
        likeCount: {
            type: Number,
            default: 0,
        },
        commentCount: {
            type: Number,
            default: 0,
        },
        total_reads: {
            type: Number,
            default: 0
        },
        total_parent_comments: {
            type: Number,
            default: 0
        },
    },
    comments: {
        type: [mongoose.Schema.Types.ObjectId],
        ref: 'comments'
    },
    draft: {
        type: Boolean,
        default: false
    }
});

const Creation = mongoose.model("creations", creationSchema);

module.exports = Creation;
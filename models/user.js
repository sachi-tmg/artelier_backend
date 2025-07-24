const mongoose = require("mongoose");

let profile_imgs_name_list = ["Garfield", "Tinkerbell", "Annie", "Loki", "Cleo", "Angel", "Bob", "Mia", "Coco", "Gracie", "Bear", "Bella", "Abby", "Harley", "Cali", "Leo", "Luna", "Jack", "Felix", "Kiki"];
let profile_imgs_collections_list = ["notionists-neutral", "adventurer-neutral", "fun-emoji"];

const userSchema = new mongoose.Schema({
    fullName: {
        type: String,
        required: true,
        index: true 
    },
    email: {
        type: String,
        required: true,
        unique: true, 
    },
    password: {
        type: String,
        required: true,
    },
    username: {
        type: String,
        unique: true,
        index: true 
    },
    profilePicture: {
        type: String, 
        default: () => {
            return `https://api.dicebear.com/6.x/${profile_imgs_collections_list[Math.floor(Math.random() * profile_imgs_collections_list.length)]}/png?seed=${profile_imgs_name_list[Math.floor(Math.random() * profile_imgs_name_list.length)]}`
        } 
    },
    coverPicture: {
        type: String,
        default: "https://localhost:3000/public/Covers/cover.png"
    },
    bio: {
        type: String,
        default: "",
    },
    link: {
        type: String,
        default: "",
    },
    account_info:{
        total_posts: {
            type: Number,
            default: 0
        },
        total_likes: {
            type: Number,
            default: 0
        },
    },
    creations: {
        type: [ mongoose.Schema.Types.ObjectId ],
        ref: 'creations',
        default: [],
    },
    favorites: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'creations',
        default: [] 
    }],
    following: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'users',
        default: []
    }],
    followers: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'users',
        default: []
    }],
    passwordResetToken: {
        type: String,
        default: null
    },
    passwordResetExpires: {
        type: Date,
        default: null
    },
    emailVerificationToken: {
        type: String,
        default: null
    },
    emailVerificationExpires: {
        type: Date,
        default: null
    },
    isVerified: { 
        type: Boolean, 
        default: false 
    },
    isBanned: {
        type: Boolean,
        default: false
    },
    loginAttempts: {
        type: Number,
        default: 0
    },
    loginLockUntil: {
        type: Date,
        default: null
    },
    lastActive: {
        type: Date,
        default: null
    },
    mfaEnabled: { type: Boolean, default: false },
        mfaSecret: String,       
        backupCodes: [          
            {
            code: String,
            used: { type: Boolean, default: false }
            }
        ],
    mfaOtp: String,
    mfaOtpExpires: Date,

    loggedInOnce: {
        type: Boolean,
        default: false
    },
    dateCreated: {
            type: Date,
            default: Date.now, 
        },
    notificationPreferences: {
        likes: { type: Boolean, default: true },
        comments: { type: Boolean, default: true },
        follows: { type: Boolean, default: true },
        purchases: { type: Boolean, default: true },
        commentReplies: { type: Boolean, default: true },
        commentLikes: { type: Boolean, default: true }
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    }
    });

const User = mongoose.model("users", userSchema);

module.exports = User;
// controllers/favorite_controller.js
const mongoose = require("mongoose");

const User = require('../models/user');
const Creation = require('../models/creation');

// Function to toggle a creation in user's favorites
exports.toggleFavorite = async (req, res) => {
    // //console.log('[toggleFavorite] Request received');
    // //console.log('[toggleFavorite] Headers:', req.headers);
    // //console.log('[toggleFavorite] Body:', req.body);
    
    const userId = req.user.userId; // Assuming userId is populated from JWT
    const { creationId } = req.body; // The _id of the creation

    // //console.log('[toggleFavorite] userId:', userId);
    // //console.log('[toggleFavorite] creationId:', creationId);

    if (!creationId) {
        // //console.log('[toggleFavorite] Error: Creation ID is required');
        return res.status(400).json({ message: 'Creation ID is required.' });
    }

    // Validate creationId format early
    if (!mongoose.Types.ObjectId.isValid(creationId)) {
        // //console.log('[toggleFavorite] Error: Invalid Creation ID format');
        return res.status(400).json({ message: 'Invalid Creation ID format.' });
    }

    try {
        // //console.log('[toggleFavorite] Looking for user:', userId);
        const user = await User.findById(userId);
        if (!user) {
            // //console.log('[toggleFavorite] Error: User not found');
            return res.status(404).json({ message: 'User not found.' });
        }

        // //console.log('[toggleFavorite] Looking for creation:', creationId);
        const creation = await Creation.findById(creationId);
        if (!creation) {
            // //console.log('[toggleFavorite] Error: Creation not found');
            return res.status(404).json({ message: 'Creation not found.' });
        }

        const creationObjectId = new mongoose.Types.ObjectId(creationId);
        // //console.log('[toggleFavorite] Creation ObjectId:', creationObjectId);

        // Correctly check if the creationObjectId is in the favorites array
        const isCurrentlyFavorite = user.favorites.some(favId => favId.equals(creationObjectId));
        // //console.log('[toggleFavorite] Current favorite status:', isCurrentlyFavorite);

        let message;
        let isFavoriteStatus;

        if (isCurrentlyFavorite) {
            // Remove from favorites
            // //console.log('[toggleFavorite] Removing from favorites');
            user.favorites.pull(creationObjectId);
            message = 'Creation removed from favorites.';
            isFavoriteStatus = false;
        } else {
            // Add to favorites
            // //console.log('[toggleFavorite] Adding to favorites');
            user.favorites.push(creationObjectId);
            message = 'Creation added to favorites.';
            isFavoriteStatus = true;
        }

        // //console.log('[toggleFavorite] Saving user with updated favorites');
        await user.save();
        
        // //console.log('[toggleFavorite] Successfully updated favorites');
        res.status(200).json({
            success: true,
            message,
            isFavorite: isFavoriteStatus,
        });

    } catch (error) {
        console.error('[toggleFavorite] Error:', error);
        res.status(500).json({
            message: 'Server error when toggling favorite.',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

// Function to get a user's favorite creations
exports.getFavorites = async (req, res) => {
    // //console.log('[getFavorites] Request received');
    const userId = req.user.userId;

    // //console.log('[getFavorites] userId:', userId);

    if (!userId) {
        // //console.log('[getFavorites] Error: User ID not provided');
        return res.status(401).json({ message: 'Unauthorized: User ID not provided.' });
    }

    try {
        // //console.log('[getFavorites] Looking for user with populated favorites');
        const user = await User.findById(userId).populate({
            path: 'favorites',
            select: '_id creation_id title creationPicture category price forSale activity.likeCount',
            populate: {
                path: 'userId',
                select: 'username fullName'
            }
        });

        if (!user) {
            // //console.log('[getFavorites] User not found, returning empty list');
            return res.status(200).json({
                success: true,
                favorites: [],
                message: 'User not found, but returning empty favorites list.'
            });
        }

        // //console.log('[getFavorites] Raw favorites:', user.favorites);
        const favoriteCreations = user.favorites.filter(c => c !== null);
        // //console.log('[getFavorites] Filtered favorites:', favoriteCreations);

        res.status(200).json({
            success: true,
            favorites: favoriteCreations,
        });

    } catch (error) {
        console.error('[getFavorites] Error:', error);
        res.status(500).json({
            message: 'Server error when fetching favorites.',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

// Function to check if a specific creation is favorited by the current user
exports.checkFavoriteStatus = async (req, res) => {
    // //console.log('[checkFavoriteStatus] Request received');
    // //console.log('[checkFavoriteStatus] Params:', req.params);
    
    const userId = req.user.userId;
    const { creationId } = req.params;

    // //console.log('[checkFavoriteStatus] userId:', userId);
    // //console.log('[checkFavoriteStatus] creationId:', creationId);

    if (!userId) {
        // //console.log('[checkFavoriteStatus] Error: User ID not provided');
        return res.status(401).json({ message: 'Unauthorized: User ID not provided.' });
    }
    if (!creationId) {
        // //console.log('[checkFavoriteStatus] Error: Creation ID is required');
        return res.status(400).json({ message: 'Creation ID is required.' });
    }
    if (!mongoose.Types.ObjectId.isValid(creationId)) {
        // //console.log('[checkFavoriteStatus] Error: Invalid Creation ID format');
        return res.status(400).json({ message: 'Invalid Creation ID format.' });
    }

    try {
        ////console.log('[checkFavoriteStatus] Looking for user:', userId);
        const user = await User.findById(userId);
        if (!user) {
            // //console.log('[checkFavoriteStatus] User not found, returning isFavorite: false');
            return res.status(200).json({ isFavorite: false, message: 'User not found.' });
        }

        const creationObjectId = new mongoose.Types.ObjectId(creationId);
        // //console.log('[checkFavoriteStatus] Checking if creation is in favorites');
        const isFavorite = user.favorites.some(favId => favId.equals(creationObjectId));
        // //console.log('[checkFavoriteStatus] isFavorite:', isFavorite);

        res.status(200).json({ isFavorite });

    } catch (error) {
        console.error('[checkFavoriteStatus] Error:', error);
        res.status(500).json({
            message: 'Server error when checking favorite status.',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};
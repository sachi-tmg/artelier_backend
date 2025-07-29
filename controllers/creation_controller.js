const Creation = require("../models/creation");
const User = require("../models/user"); 
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require('uuid');

// Moved verifyJWT here for completeness, assuming it's in the same file or imported
const verifyJWT = (req, res, next) => {
    const token = req.cookies?.token;

    if (!token) {
    return res.status(401).json({ success: false, message: "No token provided" });
    }

    jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
        if(err) {
            return res.status(403).json({ error: "Access token is invalid" })
        }

        req.user = user
        next()
        
    })
};


const publishCreation = async (req, res) => {
    try {
        let { title, des, creationPicture, category, materials, dimension, price, forSale, id, draft } = req.body;

        const userId = req.user.userId; // Assuming userId is correctly populated by verifyJWT

        // Validate user
        const user = await User.findById(userId);
        if (!user) {
            return res.status(400).json({ message: "Invalid user ID or user not found" });
        }

        // Handle localhost image URL replacement if necessary
        if (!creationPicture) {
            return res.status(400).json({ message: 'Creation picture URL is required' });
        }

        // Generate creation_id if it's a new creation, otherwise use the provided id
        let creation_id = id;
        if (!id) {
            creation_id = title.replace(/[^a-zA-Z0-9]/g, ' ').replace(/\s+/g,"-").trim() + '-' + uuidv4();
        }

        const creationData = {
            userId,
            creation_id,
            title,
            des, 
            category,
            materials,
            creationPicture,
            draft: Boolean(draft),
            dimension: dimension || null, 
            price: forSale ? parseFloat(price) : 0, 
            forSale: Boolean(forSale),
            dateUpdated: Date.now(), 
        };

        if (id) {
            // Update an existing creation
            const updatedCreation = await Creation.findOneAndUpdate(
                { creation_id: id, userId: userId }, // Find by creation_id and userId
                { $set: creationData }, // Use $set to update specific fields
                { new: true, runValidators: true } // Return the new document and run schema validators
            );

            if (!updatedCreation) {
                return res.status(404).json({ error: "Creation not found or unauthorized to update" });
            }
            return res.status(200).json({ id: updatedCreation.creation_id });

        } else {
            // Create a new creation
            const newCreation = new Creation(creationData);
            const savedCreation = await newCreation.save();

            // Increment total_posts if it's not a draft
            const incrementVal = draft ? 0 : 1;
            
            await User.findOneAndUpdate( // Assuming 'User' model now holds 'account_info.total_posts'
                { _id: userId }, 
                { 
                    $inc : {"account_info.total_posts" : incrementVal}, 
                    $push : {"creations": savedCreation._id}, // Assuming you want to push the saved _id
                },
            );
            return res.status(200).json({ id: savedCreation.creation_id });
        }

    } catch (e) {
        console.error("Error publishing creation:", e); 
        res.status(500).json({ message: "Server error", error: e.message });
    }
};

// Handle Image Upload
const uploadImage = async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: "Please upload a file" });
    }

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const imageUrl = `${baseUrl}/public/Creations/${req.file.filename}`; 

    res.status(200).json({
        success: true,
        filename: imageUrl,
    });
};

const findAllCreations = async (req, res) => {
    try {
        let { page } = req.body;
        let maxLimit = 15;

        // Fetch creations with populated user info
        const creations = await Creation.find({ draft: false })
            .populate({
                path: "userId",
                select: "fullName email username profilePicture",
            })
            .sort({ dateCreated: -1 })
            .select("creation_id title des creationPicture category materials dimension forSale price activity tags dateCreated userId _id")
            .skip((page - 1) * maxLimit)
            .limit(maxLimit);

        // Format the response
        const formattedCreations = creations.map(creation => {
            const creationObj = creation.toObject();
            if (creationObj.userId && creationObj.userId._id) {
                delete creationObj.userId._id;
            }

            return {
                ...creationObj,
                profilePicture: creationObj.userId?.profilePicture,
            };
        });

        return res.status(200).json({ creations: formattedCreations });
    } catch (e) {
        console.error("Error fetching creations:", e);
        return res.status(500).json({ message: "Server error", error: e.message });
    }
};

// New: Count total latest creations (for pagination)
const countAllCreations = async (req, res) => {
    try {
        const count = await Creation.countDocuments({ draft: false });
        return res.status(200).json({ count });
    } catch (e) {
        console.error("Error counting all creations:", e);
        return res.status(500).json({ message: "Server error", error: e.message });
    }
};

const getFeaturedCreations = async (req, res) => {
  try {
    const creations = await Creation.aggregate([
      { $match: { draft: false } },
      { $sample: { size: 12 } }, // Pick 12 random creations
      {
        $lookup: {
          from: "users",
          localField: "userId",
          foreignField: "_id",
          as: "userId"
        }
      },
      { $unwind: "$userId" },
      { $project: {
        creation_id: 1,
        title: 1,
        creationPicture: 1,
        category: 1,
        forSale: 1,
        price: 1,
        activity: 1,
        userId: {
          fullName: "$userId.fullName",
          profilePicture: "$userId.profilePicture"
        }
      }}
    ]);
    res.status(200).json({ creations });
  } catch (e) {
    console.error("Error fetching featured (random) creations:", e);
    res.status(500).json({ message: "Server error", error: e.message });
  }
};



const searchCreations = async (req, res) => {
    let { query, tag, page } = req.body;
    let maxLimit = 5;

    console.log("Backend: searchCreations controller received:", { query, tag, page });

    let findQuery = { draft: false }; // Base query: only published creations

    // Build the general search query ($or) if 'query' is provided
    if (query) {
        const searchRegex = new RegExp(query, 'i'); // Case-insensitive regex
        findQuery.$or = [
            { title: searchRegex },
            { tags: searchRegex },
            { materials: searchRegex },
            { category: searchRegex }, 
        ];
    }

    if (tag) {
        if (findQuery.$or) {
            findQuery = {
                $and: [
                    { draft: false },
                    { category: tag }, 
                    { $or: findQuery.$or } 
                ]
            };
        } else {
            findQuery.category = tag;
        }
    }
    
    console.log("Backend: MongoDB findQuery constructed:", JSON.stringify(findQuery, null, 2));

    try {
        const creations = await Creation.find(findQuery)
            .populate({
                path: "userId",
                select: "fullName email username profilePicture",
            })
            .sort({ dateCreated: -1 })
            .select("creation_id title des creationPicture category materials dimension price activity tags dateCreated userId _id forSale")
            .skip((page - 1) * maxLimit)
            .limit(maxLimit);

        const formattedCreations = creations.map(creation => {
            const creationObj = creation.toObject();
            const userDetails = creationObj.userId;
            delete creationObj.userId;

            return {
                ...creationObj,
                fullName: userDetails ? userDetails.fullName : null,
                email: userDetails ? userDetails.email : null,
                username: userDetails ? userDetails.username : null,
                profilePicture: userDetails ? userDetails.profilePicture : null,
            };
        });

        const totalDocs = await Creation.countDocuments(findQuery);

        console.log(`Backend: Found ${creations.length} creations. Total docs matching query: ${totalDocs}`);
        
        return res.status(200).json({ creations: formattedCreations, totalDocs });
    } catch (e) {
        console.error("Backend: Error searching creations:", e.message, e.stack);
        return res.status(500).json({ message: "Server error", error: e.message });
    }
};

const countSearchCreations = async (req, res) => {
    let { query, tag } = req.body;

    console.log("Backend: countSearchCreations controller received:", { query, tag });

    let findQuery = { draft: false };

    if (query) {
        const searchRegex = new RegExp(query, 'i');
        findQuery.$or = [
            { title: searchRegex },
            { tags: searchRegex },
            { materials: searchRegex },
            { category: searchRegex }, // <--- ADD THIS LINE here as well
        ];
    }

    if (tag) {
         if (findQuery.$or) {
            findQuery = {
                $and: [
                    { draft: false },
                    { category: tag },
                    { $or: findQuery.$or }
                ]
            };
        } else {
            findQuery.category = tag;
        }
    }

    console.log("Backend: MongoDB countQuery constructed:", JSON.stringify(findQuery, null, 2));

    try {
        const count = await Creation.countDocuments(findQuery);
        console.log(`Backend: Counted ${count} documents for search.`);
        return res.status(200).json({ count });
    } catch (e) {
        console.error("Backend: Error counting search creations:", e.message, e.stack);
        return res.status(500).json({ message: "Server error", error: e.message });
    }
};


// Placeholder for trending creations (you'll need to define how trending is determined)
const getTrendingCreations = async (req, res) => {
    try {
        const trending = await Creation.find({ draft: false })
            .populate({
                path: "userId",
                select: "fullName email username profilePicture",
            })
            .sort({ "activity.likeCount": -1, dateCreated: -1 })
            .limit(10)
            .select("creation_id title des creationPicture category materials dimension price activity tags dateCreated userId -_id");

        const formattedTrending = trending.map(creation => {
            const creationObj = creation.toObject();
            const userDetails = creationObj.userId;
            delete creationObj.userId;

            return {
                ...creationObj,
                fullName: userDetails ? userDetails.fullName : null,
                email: userDetails ? userDetails.email : null,
                username: userDetails ? userDetails.username : null,
                profilePicture: userDetails ? userDetails.profilePicture : null,
            };
        });

        return res.status(200).json({ creations: formattedTrending });
        
    } catch (e) {
        console.error("creation_controller.js: Error fetching trending creations:", e);
        // Ensure this catch block sends a 500, not a 404, for server errors
        return res.status(500).json({ message: "Server error", error: e.message });
    }
};


const getCreationDetails = async (req, res) => {
    try {
        const { creation_id } = req.params; // Get the creation_id from URL parameters

        if (!creation_id) {
            return res.status(400).json({ message: "Creation ID is required." });
        }

        // IMPORTANT: Select 'creationPicture' (singular), NOT 'creationPictures'
        const creation = await Creation.findOne({ creation_id: creation_id })
            .populate({
                path: "userId", // Populate the user details associated with the creation
                select: "fullName email username profilePicture account_info.bio", // Select specific fields from the User model, including bio
            })
            .select(
                "creation_id title des creationPicture category materials dimension forSale price activity tags dateCreated userId _id"
            ); // Select all necessary fields, using 'creationPicture' (singular) and 'dimension' (singular)

        if (!creation) {
            return res.status(404).json({ message: "Creation not found." });
        }

        // Format the response to include artist details directly on the main object
        const creationObj = creation.toObject();
        const userDetails = creationObj.userId;
        delete creationObj.userId; // Remove the nested userId object

        const formattedCreation = {
            ...creationObj,
            fullName: userDetails ? userDetails.fullName : null,
            email: userDetails ? userDetails.email : null,
            username: userDetails ? userDetails.username : null,
            profilePicture: userDetails ? userDetails.profilePicture : null,
            artistBio: userDetails ? userDetails.account_info?.bio : null, 
            dimension: creationObj.dimension === undefined ? null : creationObj.dimension,
        };

        return res.status(200).json({ data: formattedCreation }); // Wrap in 'data' as your frontend expects
    } catch (e) {
        console.error("Error fetching creation details:", e);
        return res.status(500).json({ message: "Server error", error: e.message });
    }
};


// Add to creation_controller.js
const getCreationsByUser = async (req, res) => {
  try {
    const userId = req.query.user;
    
    if (!userId) {
      return res.status(400).json({ message: "User ID is required" });
    }

    const creations = await Creation.find({ 
      userId: userId,
      draft: false 
    })
    .sort({ dateCreated: -1 })
    .select("creation_id title des creationPicture category materials dimension forSale price activity _id");

    res.status(200).json(creations);
  } catch (e) {
    console.error("Error fetching user creations:", e);
    res.status(500).json({ message: "Server error", error: e.message });
  }
};


const deleteCreation = async (req, res) => {
    try {
        const { creation_id } = req.params;
        const userId = req.user.userId;

        // Find and delete the creation, ensuring it belongs to the user
        const deletedCreation = await Creation.findOneAndDelete({ 
            creation_id: creation_id,
            userId: userId
        });

        if (!deletedCreation) {
            return res.status(404).json({ 
                error: "Creation not found or you don't have permission to delete it" 
            });
        }

        // Decrement user's total_posts if it wasn't a draft
        if (!deletedCreation.draft) {
            await User.findByIdAndUpdate(
                userId,
                { $inc: { "account_info.total_posts": -1 } }
            );
        }

        res.status(200).json({ message: "Creation deleted successfully" });
    } catch (e) {
        console.error("Error deleting creation:", e);
        res.status(500).json({ message: "Server error", error: e.message });
    }
};


const updateCreation = async (req, res) => {
    try {
        const { creation_id } = req.params;
        const userId = req.user.userId;
        const updateData = req.body;

        // Remove fields that shouldn't be updated
        delete updateData.creation_id;
        delete updateData.userId;
        delete updateData.dateCreated;
        delete updateData.activity;

        // Add dateUpdated
        updateData.dateUpdated = Date.now();

        const updatedCreation = await Creation.findOneAndUpdate(
            { creation_id, userId }, // Ensure only owner can update
            { $set: updateData },
            { new: true, runValidators: true }
        ).populate('userId', 'fullName username profilePicture');

        if (!updatedCreation) {
            return res.status(404).json({ 
                error: "Creation not found or you don't have permission to edit it" 
            });
        }

        // Format the response similarly to getCreationDetails
        const creationObj = updatedCreation.toObject();
        const userDetails = creationObj.userId;
        delete creationObj.userId;

        const formattedCreation = {
            ...creationObj,
            fullName: userDetails?.fullName,
            username: userDetails?.username,
            profilePicture: userDetails?.profilePicture,
            artistBio: userDetails?.account_info?.bio,
        };

        res.status(200).json({ data: formattedCreation });
    } catch (e) {
        console.error("Error updating creation:", e);
        res.status(500).json({ message: "Server error", error: e.message });
    }
};

// In your creation controller
const textSearchCreations = async (req, res) => {
  const { query, page } = req.body;
  const maxLimit = 5;
  
  try {
    const creations = await Creation.find({
      $text: { $search: query },
      draft: false
    })
    .populate("userId", "fullName username profilePicture")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit);
    
    res.status(200).json({ creations });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};


const buildCreationSearchQuery = ({ tag, query, userId, eliminate_creation_id }) => {
    let findQuery = { draft: false }; // Always exclude drafts

    if (tag) {
        // Assuming 'category' can act as a single tag, or if you added a 'tags' array:
        // findQuery.tags = tag; // if you added a 'tags' array
        findQuery.category = tag; // Use category for now as per your schema
    } else if (query) {
        // Search by title or description (case-insensitive)
        findQuery.$or = [
            { title: new RegExp(query, 'i') },
            { des: new RegExp(query, 'i') }
        ];
    } else if (userId) {
        findQuery.userId = userId;
    }

    if (eliminate_creation_id) {
        findQuery.creation_id = { $ne: eliminate_creation_id };
    }

    return findQuery;
};

// Consolidated search function for creations (for both count and data)
const searchCreationsGeneralized = async (req, res) => {
    try {
        let { tag, query, userId, page, eliminate_creation_id, countOnly = false } = req.body;
        let maxLimit = 9; // Default limit, adjust as needed

        const findQuery = buildCreationSearchQuery({ tag, query, userId, eliminate_creation_id });

        if (countOnly) {
            // Only return the count
            const count = await Creation.countDocuments(findQuery);
            return res.status(200).json({ totalDocs: count });
        }

        // Otherwise, return the paginated creations
        const creations = await Creation.find(findQuery)
            .populate({
                path: "userId",
                select: "fullName email username profilePicture account_info.bio", // Include bio if needed
            })
            .sort({ dateCreated: -1 })
            .select("creation_id title des creationPicture category materials dimension forSale price activity tags dateCreated userId _id")
            .skip((page - 1) * maxLimit)
            .limit(maxLimit);

        // Format the response to flatten user details and include profilePicture directly
        const formattedCreations = creations.map(creation => {
            const creationObj = creation.toObject();
            const userDetails = creationObj.userId;

            // Remove the nested userId object and flatten artist details
            delete creationObj.userId;

            return {
                ...creationObj,
                fullName: userDetails ? userDetails.fullName : null,
                email: userDetails ? userDetails.email : null,
                username: userDetails ? userDetails.username : null,
                profilePicture: userDetails ? userDetails.profilePicture : null,
                artistBio: userDetails ? userDetails.account_info?.bio : null, // Access bio from account_info
            };
        });

        return res.status(200).json({ creations: formattedCreations });

    } catch (e) {
        console.error("Error searching creations:", e);
        return res.status(500).json({ message: "Server error", error: e.message });
    }
};


module.exports = {
    verifyJWT,
    uploadImage,
    publishCreation,
    findAllCreations,
    searchCreations,
    countAllCreations,
    countSearchCreations,
    getTrendingCreations,
    getCreationDetails,
    getCreationsByUser,
    deleteCreation,
    updateCreation,
    textSearchCreations,
    buildCreationSearchQuery,
    searchCreationsGeneralized,
    getFeaturedCreations
};
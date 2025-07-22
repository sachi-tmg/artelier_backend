// const express = require("express");
// const {
//     verifyJWT,
//     publishCreation,
//     uploadImage,
//     findAllCreations,
//     searchCreations,
//     countAllCreations,
//     countSearchCreations,
//     getTrendingCreations,
//     getCreationDetails
// } = require("../controllers/creation_controller");
// const uploads = require("../middleware/upload_image");

// const router = express.Router();

// router.post("/publish-creation", verifyJWT, uploads, publishCreation);
// router.post("/creationImage", uploads, uploadImage);
// router.post("/latest-creations", findAllCreations); 
// router.get("/trending-creations", getTrendingCreations);
// router.get("/:creation_id", getCreationDetails); 


// routes/creation_route.js
const express = require("express");
const router = express.Router();

const creationController = require("../controllers/creation_controller");
const uploads = require("../middleware/upload_image");

const {
    verifyJWT,
    publishCreation,
    uploadImage,
    findAllCreations,
    searchCreations,
    countAllCreations,
    countSearchCreations,
    getTrendingCreations,
    getCreationDetails,
    getCreationsByUser,
    deleteCreation,
    updateCreation,
} = creationController;

// --- Place more specific routes first ---

router.post("/publish-creation", verifyJWT, uploads, publishCreation);

router.post("/creationImage", uploads, uploadImage);

router.post("/latest-creations", findAllCreations);

router.post("/search-creations", searchCreations);

router.get("/count-all-creations", countAllCreations);

router.post("/count-search-creations", countSearchCreations);

router.get("/featured-creations", creationController.getFeaturedCreations);

// IMPORTANT: This is the route we are debugging - place it BEFORE /:creation_id
router.get("/trending-creations", (req, res, next) => {
    next(); // Pass control to the actual controller
}, getTrendingCreations);


// --- Place the general/parameterized route last ---
router.get("/:creation_id", (req, res, next) => {
    next(); // Pass control to the actual controller
}, getCreationDetails);

router.get("/", getCreationsByUser);

router.delete("/:creation_id", verifyJWT, deleteCreation);

router.put("/:creation_id", verifyJWT, uploads, updateCreation);

module.exports = router;








// router.post("/all-latest-blogs-count", countRoute);
// router.post("/search-blogs", searchInBlogs);
// router.post("/search-blogs-count", countSearchRoute);
// router.post("/blog-view", getFullBlog);
// router.post("/like-blog", verifyJWT,likeBlog);
// router.post("/is-liked-by-user", verifyJWT,isLiked);
// router.get("/new-notification", verifyJWT,notificationsAvailability);
// router.post("/notifications", verifyJWT,gettingNotifications);
// router.post("/all-notifications-count", verifyJWT,notificationCount);
// router.post("/user-written-blogs", verifyJWT,userBlog);
// router.post("/user-written-blogs-count", verifyJWT,countUserBlog);
// router.post("/delete-blog", verifyJWT,deletingBlog);

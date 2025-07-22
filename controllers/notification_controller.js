const Notification = require('../models/notification');

exports.notificationsAvailability = async (req, res) => {
    try {
        const userId = req.user.userId;
        
        const hasNewNotifications = await Notification.exists({ 
            notification_for: userId, 
            seen: false, 
            user: { $ne: userId } 
        });

        res.status(200).json({ 
            new_notification_available: !!hasNewNotifications 
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: err.message });
    }
};

exports.getNotifications = async (req, res) => {
    try {
        const userId = req.user.userId;
        const { page = 1, filter = 'all', deletedDocCount = 0 } = req.body;
        const maxLimit = 10;

        let findQuery = { 
            notification_for: userId, 
            user: { $ne: userId } 
        };

        if (filter !== 'all') {
            findQuery.type = filter;
        }

        const skipDocs = Math.max(0, (page - 1) * maxLimit - deletedDocCount);

        const notifications = await Notification.find(findQuery)
            .skip(skipDocs)
            .limit(maxLimit)
            .populate("creation", "title creation_id creationPicture")
            .populate("user", "fullName username profilePicture")
            .populate("comment", "content")
            .sort({ createdAt: -1 })
            .select("createdAt type seen");

        // Mark as seen
        await Notification.updateMany(
            { _id: { $in: notifications.map(n => n._id) } },
            { seen: true }
        );

        res.status(200).json({ notifications });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: err.message });
    }
};

exports.notificationCount = async (req, res) => {
    try {
        const userId = req.user.userId;
        const { filter = 'all' } = req.body;

        let findQuery = { 
            notification_for: userId, 
            user: { $ne: userId } 
        };

        if (filter !== 'all') {
            findQuery.type = filter;
        }

        const count = await Notification.countDocuments(findQuery);
        res.status(200).json({ totalDocs: count });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};
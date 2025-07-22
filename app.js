require("dotenv").config();

const express = require("express");
const connectDB = require("./config/db");
const user_router = require("./routes/user_route");
const creation_router = require("./routes/creation_route");
const cartRoutes = require("./routes/cart_route");
const payment_router = require("./routes/payment_route");
const favorite_router = require("./routes/favorite_route");
const notificationRoutes = require('./routes/notification_route');
const like_router = require("./routes/like_route");
const commentRoutes = require('./routes/comment_route');
const orderRoutes = require('./routes/order_route');
const contact_route = require('./routes/contact_route');
const cors = require("cors");

const app = express();

connectDB();

const corsOptions = {
    origin: "http://localhost:5173",
    credentials: true,
    optionSuccessStatus: 200,
};

app.use(cors(corsOptions));
app.use(express.json());

app.use("/api/user", user_router);
app.use("/api/creation", creation_router);
app.use("/api/cart", cartRoutes);

app.use("/api/payment", payment_router);
app.use("/api/favorite", favorite_router);
app.use('/api/notifications', notificationRoutes);
app.use('/api', like_router);

app.use('/api/comments', commentRoutes);

app.use('/api/orders', orderRoutes);

app.use('/api/contact', contact_route);

app.use("/public", express.static('public'));

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});

module.exports = app;

require("dotenv").config();

const https = require('https');
const fs = require('fs');
const path = require('path');

const express = require("express");
const helmet = require("helmet");
const mongoSanitize = require('express-mongo-sanitize');
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
const admin_router = require('./routes/admin_route');
const csrf_route = require('./routes/csrf_route');
const auditMiddleware = require('./middleware/audit_middleware');
const { csrfProtection } = require('./middleware/csrf_protection');
const SanitizationMiddleware = require('./middleware/sanitization_middleware');
const cors = require("cors");

const app = express();

connectDB();

// Helmet security configuration - protecting against common web vulnerabilities
app.use(helmet({
  // Content Security Policy - configured for your image uploads and frontend
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:", "blob:"], // Allow images from various sources
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      connectSrc: ["'self'", "https://localhost:5173", "https://localhost:3000"], // Allow connections to your frontend and backend
      frameSrc: ["'none'"],
    },
  },
  
  // Cross-Origin Embedder Policy - disabled for CORS compatibility
  crossOriginEmbedderPolicy: false,
  
  // Cross-Origin Resource Policy - disabled for CORS compatibility  
  crossOriginResourcePolicy: false,
  
  // Strict Transport Security - enforce HTTPS
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  },
  
  // Hide X-Powered-By header
  hidePoweredBy: true,
  
  // X-Frame-Options - prevent clickjacking
  frameguard: { action: 'deny' },
  
  // X-Content-Type-Options - prevent MIME sniffing
  noSniff: true,
  
  // Referrer Policy
  referrerPolicy: { policy: "same-origin" }
}));

const httpsOptions = {
  key: fs.readFileSync('C:/Users/sachi/certs/localhost-key.pem'),
  cert: fs.readFileSync('C:/Users/sachi/certs/localhost-cert.pem')
};

const corsOptions = {
    origin: "https://localhost:5173",
    credentials: true,
    optionSuccessStatus: 200,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-csrf-token'],
};

app.use(cors(corsOptions));
app.use(express.json());

// NoSQL injection prevention
app.use(mongoSanitize());

const cookieParser = require("cookie-parser");
app.use(cookieParser());

// Add input sanitization middleware (before audit middleware)
app.use(SanitizationMiddleware.sanitizeInput());

// Add audit middleware to log all API requests
app.use('/api', auditMiddleware({
  skipPaths: ['/health', '/ping', '/favicon.ico']
}));

// CSRF protection routes (no CSRF needed for getting token)
app.use('/api/csrf', csrf_route);

// Apply CSRF protection to state-changing routes
const csrfMiddleware = csrfProtection({
  skipMethods: ['GET', 'HEAD', 'OPTIONS'],
  headerName: 'x-csrf-token'
});

app.use("/api/user", csrfMiddleware, user_router);
app.use("/api/creation", csrfMiddleware, creation_router);
app.use("/api/cart", csrfMiddleware, cartRoutes);
app.use('/api/admin', csrfMiddleware, admin_router); 
app.use("/api/payment", csrfMiddleware, payment_router);
app.use("/api/favorite", csrfMiddleware, favorite_router);
app.use('/api/notifications', csrfMiddleware, notificationRoutes);
app.use('/api', csrfMiddleware, like_router);
app.use('/api/comments', commentRoutes);
app.use('/api/orders', orderRoutes);
app.use('/api/contact', csrfMiddleware, contact_route);

app.use("/public", express.static('public'));

const port = process.env.PORT || 3000;
const server = https.createServer(httpsOptions, app).listen(port, () => {
    console.log(`Server running at HTTPS://localhost:${port}`);
});


module.exports = app;

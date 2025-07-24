const adminAuth = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    return next();
  }
  res.status(403).json({
    success: false,
    message: "Admin privileges required"
  });
};

module.exports = adminAuth;
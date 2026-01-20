// backend/src/middlewares/authorize.js

const hasPermission = require('../utils/hasPermission');

const authorize = (action) => {
  return (req, res, next) => {
    const role = req.user?.role; // set by auth middleware

    if (!hasPermission(role, action)) {
      return res.status(403).json({
        message: 'Access denied: insufficient permissions',
      });
    }

    next();
  };
};

module.exports = authorize;


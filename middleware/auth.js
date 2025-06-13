const jwt = require('jsonwebtoken');
const User = require('../models/User');
const AppError = require('../utils/appError');

module.exports = {
  // Verify JWT token
  verifyToken: async (req, res, next) => {
    try {
      // 1) Check if token exists
      let token;
      if (
        req.headers.authorization &&
        req.headers.authorization.startsWith('Bearer')
      ) {
        token = req.headers.authorization.split(' ')[1];
      }

      if (!token) {
        return next(
          new AppError('You are not logged in! Please log in to get access.', 401)
        );
      }

      // 2) Verify token
      const decoded = await jwt.verify(token, process.env.JWT_SECRET);

      // 3) Check if user still exists
      const currentUser = await User.findById(decoded.id);
      if (!currentUser) {
        return next(
          new AppError('The user belonging to this token no longer exists.', 401)
        );
      }

      // 4) Check if user changed password after token was issued
      if (currentUser.changedPasswordAfter(decoded.iat)) {
        return next(
          new AppError('User recently changed password! Please log in again.', 401)
        );
      }

      // 5) Grant access to protected route
      req.user = currentUser;
      res.locals.user = currentUser;
      next();
    } catch (err) {
      next(err);
    }
  },

  // Role-based authorization
  restrictTo: (...roles) => {
    return (req, res, next) => {
      if (!roles.includes(req.user.role)) {
        return next(
          new AppError('You do not have permission to perform this action', 403)
        );
      }
      next();
    };
  },

  // Email verification check
  checkVerified: async (req, res, next) => {
    if (!req.user.emailVerified) {
      return next(
        new AppError('Please verify your email address to access this resource', 403)
      );
    }
    next();
  }
};

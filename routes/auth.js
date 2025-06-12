const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
const User = require('../models/User');
const crypto = require('crypto');
const sendEmail = require('../utils/email');

// Helper for standardized error responses
const errorResponse = (res, code, message, details = null) => {
  return res.status(code).json({
    success: false,
    error: {
      code: code,
      message: message,
      details: details
    }
  });
};

// Input validation rules
const registerRules = [
  check('name', 'Name is required').not().isEmpty(),
  check('email', 'Please include a valid email').isEmail(),
  check('phone', 'Phone number is required').not().isEmpty(),
  check('password', 'Password must be 8+ characters').isLength({ min: 8 })
];

const loginRules = [
  check('email', 'Please include a valid email').isEmail(),
  check('password', 'Password is required').exists()
];

// User registration
router.post('/register', registerRules, async (req, res) => {
  try {
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return errorResponse(res, 400, 'Validation failed', errors.array());
    }

    const { name, email, phone, password, role } = req.body;
    
    // Check existing user
    const userExists = await User.findOne({ email });
    if (userExists) {
      return errorResponse(res, 409, 'Email already registered');
    }

    // Create user
    const user = new User({
      name,
      email,
      phone,
      password,
      role: role || 'patient',
      emailVerificationToken: crypto.randomBytes(20).toString('hex'),
      emailVerificationExpires: Date.now() + 24 * 60 * 60 * 1000 // 24 hours
    });

    // Hash password
    const salt = await bcrypt.genSalt(12);
    user.password = await bcrypt.hash(password, salt);

    await user.save();

    // Send verification email
    const verificationUrl = `${req.protocol}://${req.get('host')}/api/auth/verify-email/${user.emailVerificationToken}`;
    await sendEmail({
      to: user.email,
      subject: 'Verify Your Email',
      html: `<p>Click <a href="${verificationUrl}">here</a> to verify your email.</p>`
    });

    // Generate JWT
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        isVerified: false
      }
    });

  } catch (err) {
    console.error(err);
    errorResponse(res, 500, 'Server error');
  }
});

// User login
router.post('/login', loginRules, async (req, res) => {
  try {
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return errorResponse(res, 400, 'Validation failed', errors.array());
    }

    const { email, password } = req.body;

    // Check user exists
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return errorResponse(res, 401, 'Invalid credentials');
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return errorResponse(res, 401, 'Invalid credentials');
    }

    // Check email verification
    if (!user.isVerified) {
      return errorResponse(res, 403, 'Email not verified');
    }

    // Generate JWT
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified
      }
    });

  } catch (err) {
    console.error(err);
    errorResponse(res, 500, 'Server error');
  }
});

// Email verification
router.get('/verify-email/:token', async (req, res) => {
  try {
    const user = await User.findOne({
      emailVerificationToken: req.params.token,
      emailVerificationExpires: { $gt: Date.now() }
    });

    if (!user) {
      return errorResponse(res, 400, 'Invalid or expired token');
    }

    user.isVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save();

    res.status(200).json({
      success: true,
      message: 'Email verified successfully'
    });

  } catch (err) {
    console.error(err);
    errorResponse(res, 500, 'Server error');
  }
});

// Password reset request
router.post('/forgot-password', [
  check('email', 'Please include a valid email').isEmail()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return errorResponse(res, 400, 'Validation failed', errors.array());
    }

    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return errorResponse(res, 404, 'User not found');
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(20).toString('hex');
    user.passwordResetToken = resetToken;
    user.passwordResetExpires = Date.now() + 30 * 60 * 1000; // 30 minutes
    await user.save();

    // Send email
    const resetUrl = `${req.protocol}://${req.get('host')}/api/auth/reset-password/${resetToken}`;
    await sendEmail({
      to: user.email,
      subject: 'Password Reset Request',
      html: `<p>Click <a href="${resetUrl}">here</a> to reset your password.</p>`
    });

    res.json({
      success: true,
      message: 'Password reset email sent'
    });

  } catch (err) {
    console.error(err);
    errorResponse(res, 500, 'Server error');
  }
});

// Password reset
router.post('/reset-password/:token', [
  check('password', 'Password must be 8+ characters').isLength({ min: 8 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return errorResponse(res, 400, 'Validation failed', errors.array());
    }

    const user = await User.findOne({
      passwordResetToken: req.params.token,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return errorResponse(res, 400, 'Invalid or expired token');
    }

    // Update password
    const salt = await bcrypt.genSalt(12);
    user.password = await bcrypt.hash(req.body.password, salt);
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    res.json({
      success: true,
      message: 'Password updated successfully'
    });

  } catch (err) {
    console.error(err);
    errorResponse(res, 500, 'Server error');
  }
});

module.exports = router;

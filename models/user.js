const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const validator = require('validator');
const crypto = require('crypto');

/**
 * User Schema for Patna Diagnostics System
 * Includes comprehensive security features and validation
 */
const UserSchema = new mongoose.Schema({
  // Personal Information
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true,
    maxlength: [50, 'Name cannot exceed 50 characters'],
    match: [/^[a-zA-Z ]*$/, 'Name can only contain letters and spaces']
  },
  
  // Authentication Information
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email'],
    index: true,
    immutable: true // Email cannot be changed after registration
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters'],
    select: false,
    validate: {
      validator: function(v) {
        return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(v);
      },
      message: 'Password must contain at least one uppercase, one lowercase, one number and one special character'
    }
  },
  
  // Contact Information
  phone: {
    type: String,
    required: [true, 'Phone number is required'],
    validate: {
      validator: function(v) {
        return /^[0-9]{10,15}$/.test(v);
      },
      message: 'Please provide a valid phone number'
    }
  },
  address: {
    street: String,
    city: String,
    state: String,
    postalCode: String
  },
  
  // Security Fields
  passwordChangedAt: {
    type: Date,
    select: false
  },
  passwordResetToken: {
    type: String,
    select: false
  },
  passwordResetExpires: {
    type: Date,
    select: false
  },
  failedLoginAttempts: {
    type: Number,
    default: 0,
    select: false
  },
  accountLockedUntil: {
    type: Date,
    select: false
  },
  
  // Verification Fields
  emailVerified: {
    type: Boolean,
    default: false
  },
  emailVerificationToken: {
    type: String,
    select: false
  },
  emailVerificationExpires: {
    type: Date,
    select: false
  },
  phoneVerified: {
    type: Boolean,
    default: false
  },
  
  // Role Management
  role: {
    type: String,
    enum: ['patient', 'admin', 'technician', 'receptionist'],
    default: 'patient'
  },
  permissions: [String], // Fine-grained permissions
  
  // Account Status
  active: {
    type: Boolean,
    default: true,
    select: false
  },
  lastLogin: Date,
  loginHistory: [{
    timestamp: Date,
    ipAddress: String,
    userAgent: String
  }]
}, {
  timestamps: true,
  toJSON: {
    virtuals: true,
    transform: function(doc, ret) {
      // Remove sensitive fields when converting to JSON
      delete ret.password;
      delete ret.passwordResetToken;
      delete ret.passwordResetExpires;
      delete ret.failedLoginAttempts;
      delete ret.accountLockedUntil;
      return ret;
    }
  },
  toObject: { virtuals: true }
});

/**
 * Password Hashing Middleware
 */
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    // Hash password with cost factor of 12
    this.password = await bcrypt.hash(this.password, 12);
    
    // Set passwordChangedAt timestamp (except for new users)
    if (!this.isNew) {
      this.passwordChangedAt = Date.now() - 1000; // 1 second in past to ensure token works
    }
    next();
  } catch (err) {
    next(err);
  }
});

/**
 * Filter out inactive users by default
 */
UserSchema.pre(/^find/, function(next) {
  this.find({ active: { $ne: false } });
  next();
});

/**
 * Instance Methods
 */
UserSchema.methods = {
  // Verify password
  correctPassword: async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
  },
  
  // Check if password changed after token was issued
  changedPasswordAfter: function(JWTTimestamp) {
    if (this.passwordChangedAt) {
      const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
      return JWTTimestamp < changedTimestamp;
    }
    return false;
  },
  
  // Generate password reset token
  createPasswordResetToken: function() {
    const resetToken = crypto.randomBytes(32).toString('hex');
    
    this.passwordResetToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    
    this.passwordResetExpires = Date.now() + 30 * 60 * 1000; // 30 minutes
    
    return resetToken;
  },
  
  // Generate email verification token
  createEmailVerificationToken: function() {
    const verificationToken = crypto.randomBytes(32).toString('hex');
    
    this.emailVerificationToken = crypto
      .createHash('sha256')
      .update(verificationToken)
      .digest('hex');
    
    this.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    
    return verificationToken;
  },
  
  // Handle failed login attempts
  handleFailedLogin: function() {
    this.failedLoginAttempts += 1;
    if (this.failedLoginAttempts >= 5) {
      this.accountLockedUntil = Date.now() + 30 * 60 * 1000; // Lock for 30 minutes
    }
    return this.save({ validateBeforeSave: false });
  },
  
  // Reset login attempts after successful login
  resetLoginAttempts: function() {
    this.failedLoginAttempts = 0;
    this.accountLockedUntil = undefined;
    this.lastLogin = Date.now();
    return this.save({ validateBeforeSave: false });
  }
};

/**
 * Static Methods
 */
UserSchema.statics = {
  // Find user by email with case insensitivity
  findByEmail: async function(email) {
    return this.findOne({ email: new RegExp(`^${email}$`, 'i') });
  }
};

// Create compound index for faster queries
UserSchema.index({ email: 1, active: 1 });

module.exports = mongoose.model('User', UserSchema);

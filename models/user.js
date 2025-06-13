const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const validator = require('validator');
const crypto = require('crypto');

/**
 * User Schema for Patna Diagnostics System
 * Now with OTP verification and comprehensive audit logging
 */
const UserSchema = new mongoose.Schema({
  // ========== CORE USER DATA ==========
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true,
    maxlength: [50, 'Name cannot exceed 50 characters'],
    match: [/^[a-zA-Z ]*$/, 'Name can only contain letters and spaces']
  },
  
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email'],
    index: true,
    immutable: true
  },

  // ========== AUTHENTICATION ==========
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters'],
    select: false,
    validate: {
      validator: function(v) {
        return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(v);
      },
      message: 'Password must contain at least one uppercase, lowercase, number and special character'
    }
  },

  // ========== OTP VERIFICATION ==========
  otp: {
    code: String,
    expires: Date,
    purpose: {
      type: String,
      enum: ['login', 'email-verification', 'password-reset', 'transaction']
    }
  },
  otpAttempts: {
    type: Number,
    default: 0,
    select: false
  },
  otpLockedUntil: Date,

  // ========== SECURITY FIELDS ==========
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  failedLoginAttempts: {
    type: Number,
    default: 0,
    select: false
  },
  accountLockedUntil: Date,
  lastPasswordChange: Date,
  passwordHistory: [{
    password: String,
    changedAt: Date
  }],

  // ========== VERIFICATION STATUS ==========
  emailVerified: {
    type: Boolean,
    default: false
  },
  phoneVerified: {
    type: Boolean,
    default: false
  },
  kycVerified: {
    type: Boolean,
    default: false
  },

  // ========== AUDIT LOGGING ==========
  auditLog: [{
    action: String, // 'login', 'password-change', 'profile-update'
    timestamp: {
      type: Date,
      default: Date.now
    },
    ipAddress: String,
    userAgent: String,
    location: {
      type: String,
      enum: ['web', 'mobile', 'api']
    },
    metadata: mongoose.Schema.Types.Mixed
  }],

  // ========== ROLE & PERMISSIONS ==========
  role: {
    type: String,
    enum: ['patient', 'admin', 'technician', 'receptionist', 'billing'],
    default: 'patient'
  },
  permissions: [{
    type: String,
    enum: ['view-reports', 'edit-tests', 'manage-users', 'process-payments']
  }],

  // ========== ACCOUNT STATUS ==========
  active: {
    type: Boolean,
    default: true,
    select: false
  },
  deactivationReason: String,
  lastActivity: Date
}, {
  timestamps: true,
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      // Remove sensitive data from JSON output
      delete ret.password;
      delete ret.otp;
      delete ret.passwordHistory;
      delete ret.auditLog;
      return ret;
    }
  }
});

// ========== MIDDLEWARE ==========
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  // Store old password in history before hashing
  if (this.isModified('password') && !this.isNew) {
    this.passwordHistory.unshift({
      password: this.password,
      changedAt: Date.now()
    });
    
    // Keep only last 5 passwords
    if (this.passwordHistory.length > 5) {
      this.passwordHistory = this.passwordHistory.slice(0, 5);
    }
    
    this.lastPasswordChange = Date.now();
  }

  this.password = await bcrypt.hash(this.password, 12);
  this.passwordChangedAt = Date.now() - 1000;
  next();
});

// ========== INSTANCE METHODS ==========
UserSchema.methods = {
  // Password verification
  correctPassword: async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
  },

  // Check if password was changed after token issued
  changedPasswordAfter: function(JWTTimestamp) {
    if (this.passwordChangedAt) {
      const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
      return JWTTimestamp < changedTimestamp;
    }
    return false;
  },

  // Generate OTP
  createOTP: function(purpose) {
    const otpCode = crypto.randomInt(100000, 999999).toString();
    this.otp = {
      code: await bcrypt.hash(otpCode, 8),
      expires: Date.now() + 10 * 60 * 1000, // 10 minutes
      purpose: purpose
    };
    return otpCode;
  },

  // Verify OTP
  verifyOTP: async function(otpCode, purpose) {
    if (!this.otp || this.otp.purpose !== purpose) return false;
    if (this.otp.expires < Date.now()) return false;
    
    return await bcrypt.compare(otpCode, this.otp.code);
  },

  // Password reset token
  createPasswordResetToken: function() {
    const resetToken = crypto.randomBytes(32).toString('hex');
    this.passwordResetToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    this.passwordResetExpires = Date.now() + 30 * 60 * 1000; // 30 minutes
    return resetToken;
  },

  // Log security event
  logActivity: function(action, metadata = {}) {
    this.auditLog.push({
      action,
      ipAddress: metadata.ip || 'unknown',
      userAgent: metadata.userAgent || 'unknown',
      location: metadata.location || 'web',
      metadata
    });
    
    // Keep last 100 audit entries
    if (this.auditLog.length > 100) {
      this.auditLog = this.auditLog.slice(-100);
    }
    
    this.lastActivity = Date.now();
  }
};

// ========== STATIC METHODS ==========
UserSchema.statics = {
  findByEmail: async function(email) {
    return this.findOne({ email: new RegExp(`^${email}$`, 'i') });
  },
  
  isEmailTaken: async function(email, excludeUserId) {
    return this.findOne({
      email: new RegExp(`^${email}$`, 'i'),
      _id: { $ne: excludeUserId }
    });
  }
};

// Indexes
UserSchema.index({ email: 1, active: 1 });
UserSchema.index({ 'auditLog.timestamp': -1 });
UserSchema.index({ lastActivity: -1 });

module.exports = mongoose.model('User', UserSchema);

// models/User.js - User model with dynamic permissions and attributes
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    minlength: [3, 'Username must be at least 3 characters long'],
    maxlength: [50, 'Username cannot exceed 50 characters']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters long']
  },
  firstName: {
    type: String,
    required: [true, 'First name is required'],
    trim: true,
    maxlength: [50, 'First name cannot exceed 50 characters']
  },
  lastName: {
    type: String,
    required: [true, 'Last name is required'],
    trim: true,
    maxlength: [50, 'Last name cannot exceed 50 characters']
  },
  roles: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Role'
  }],
  // Direct permissions (override role permissions)
  permissions: [{
    resource: { type: String, required: true },
    actions: [{ type: String, enum: ['create', 'read', 'update', 'delete', 'execute'] }],
    conditions: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    }
  }],
  // User attributes for ABAC
  attributes: {
    department: { type: String, default: '' },
    location: { type: String, default: '' },
    level: { type: String, default: 'user' },
    team: { type: String, default: '' },
    manager: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    customAttributes: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    }
  },
  // Resource filters - what data user can access
  resourceFilters: [{
    resource: { type: String, required: true },
    filters: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    }
  }],
  isActive: {
    type: Boolean,
    default: true
  },
  lastLogin: {
    type: Date
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date
  },
  refreshTokens: [{
    token: String,
    createdAt: { type: Date, default: Date.now },
    expiresAt: Date,
    isActive: { type: Boolean, default: true }
  }],
  passwordResetToken: String,
  passwordResetExpires: Date,
  emailVerified: {
    type: Boolean,
    default: false
  },
  emailVerificationToken: String
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for full name
userSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});

// Virtual for account locked status
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Index for performance
userSchema.index({ email: 1 });
userSchema.index({ username: 1 });
userSchema.index({ 'roles': 1 });
userSchema.index({ 'attributes.department': 1 });
userSchema.index({ 'attributes.location': 1 });

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare password
userSchema.methods.comparePassword = async function(candidatePassword) {
  try {
    return await bcrypt.compare(candidatePassword, this.password);
  } catch (error) {
    throw error;
  }
};

// Method to generate JWT access token
userSchema.methods.generateAccessToken = function() {
  return jwt.sign(
    {
      userId: this._id,
      username: this.username,
      email: this.email,
      roles: this.roles,
      attributes: this.attributes
    },
    process.env.JWT_SECRET || 'your-jwt-secret',
    { expiresIn: process.env.JWT_EXPIRE || '15m' }
  );
};

// Method to generate refresh token
userSchema.methods.generateRefreshToken = function() {
  const refreshToken = jwt.sign(
    { userId: this._id },
    process.env.REFRESH_TOKEN_SECRET || 'your-refresh-secret',
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRE || '7d' }
  );

  // Store refresh token in database
  this.refreshTokens.push({
    token: refreshToken,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
  });

  return refreshToken;
};

// Method to handle login attempts
userSchema.methods.incLoginAttempts = function() {
  // If we have a previous lock that has expired, restart at 1
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  
  // Lock account after 5 failed attempts for 2 hours
  if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 };
  }
  
  return this.updateOne(updates);
};

// Method to reset login attempts
userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $unset: { loginAttempts: 1, lockUntil: 1 }
  });
};

// Method to check if user has permission for a resource and action
userSchema.methods.hasPermission = async function(resource, action, context = {}) {
  await this.populate(['roles', 'roles.permissions']);
  
  // Check direct user permissions first
  const directPermission = this.permissions.find(p => p.resource === resource);
  if (directPermission && directPermission.actions.includes(action)) {
    return this.evaluateConditions(directPermission.conditions, context);
  }
  
  // Check role-based permissions
  for (const role of this.roles) {
    const rolePermission = role.permissions.find(p => p.resource === resource);
    if (rolePermission && rolePermission.actions.includes(action)) {
      return this.evaluateConditions(rolePermission.conditions, context);
    }
  }
  
  return false;
};

// Method to evaluate ABAC conditions
userSchema.methods.evaluateConditions = function(conditions, context) {
  if (!conditions || Object.keys(conditions).length === 0) {
    return true; // No conditions means permission granted
  }
  
  // Simple condition evaluation (can be extended for complex rules)
  for (const [key, value] of Object.entries(conditions)) {
    const userValue = this.attributes[key] || context[key];
    
    if (Array.isArray(value)) {
      if (!value.includes(userValue)) return false;
    } else if (typeof value === 'object' && value.operator) {
      // Handle complex conditions like { operator: 'eq', value: 'admin' }
      switch (value.operator) {
        case 'eq':
          if (userValue !== value.value) return false;
          break;
        case 'ne':
          if (userValue === value.value) return false;
          break;
        case 'in':
          if (!value.value.includes(userValue)) return false;
          break;
        case 'nin':
          if (value.value.includes(userValue)) return false;
          break;
        default:
          return false;
      }
    } else {
      if (userValue !== value) return false;
    }
  }
  
  return true;
};

// Method to get resource filters for a user
userSchema.methods.getResourceFilters = function(resource) {
  const filter = this.resourceFilters.find(f => f.resource === resource);
  return filter ? filter.filters : {};
};

// Static method to find by credentials
userSchema.statics.findByCredentials = async function(login, password) {
  const user = await this.findOne({
    $or: [
      { email: login.toLowerCase() },
      { username: login }
    ],
    isActive: true
  }).populate('roles');

  if (!user) {
    throw new Error('Invalid credentials');
  }

  if (user.isLocked) {
    throw new Error('Account is locked due to too many failed login attempts');
  }

  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
    await user.incLoginAttempts();
    throw new Error('Invalid credentials');
  }

  // Reset login attempts on successful login
  if (user.loginAttempts > 0) {
    await user.resetLoginAttempts();
  }

  // Update last login
  user.lastLogin = new Date();
  await user.save();

  return user;
};

module.exports = mongoose.model('User', userSchema);
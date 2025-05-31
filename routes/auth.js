// routes/auth.js - Authentication routes with JWT and refresh tokens
const express = require('express');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Role = require('../models/Role');
const { sendEmail } = require('../utils/email');

const router = express.Router();

// Rate limiting for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: 'Too many authentication attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // limit each IP to 3 reset requests per hour
  message: 'Too many password reset attempts, please try again later.'
});

// Validation middleware
const registerValidation = [
  body('username')
    .isLength({ min: 3, max: 50 })
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username must be 3-50 characters and contain only letters, numbers, and underscores'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .isLength({ min: 6 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must be at least 6 characters with uppercase, lowercase, and number'),
  body('firstName')
    .isLength({ min: 1, max: 50 })
    .trim()
    .withMessage('First name is required and must be less than 50 characters'),
  body('lastName')
    .isLength({ min: 1, max: 50 })
    .trim()
    .withMessage('Last name is required and must be less than 50 characters')
];

const loginValidation = [
  body('login')
    .notEmpty()
    .withMessage('Username or email is required'),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

// GET /auth/login - Login page
router.get('/login', (req, res) => {
  if (req.session.user) {
    return res.redirect('/dashboard');
  }
  
  res.render('auth/login', {
    title: 'Login',
    error: req.query.error,
    message: req.query.message,
    user: null
  });
});

// POST /auth/login - Login user
router.post('/login', authLimiter, loginValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.render('auth/login', {
        title: 'Login',
        error: errors.array()[0].msg,
        user: null
      });
    }

    const { login, password, rememberMe } = req.body;
    
    const user = await User.findByCredentials(login, password);
    
    // Generate tokens
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();
    await user.save();

    // Set session
    req.session.user = {
      id: user._id,
      username: user.username,
      email: user.email,
      fullName: user.fullName,
      roles: user.roles,
      attributes: user.attributes
    };

    // Set cookies
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    };

    res.cookie('accessToken', accessToken, {
      ...cookieOptions,
      maxAge: 15 * 60 * 1000 // 15 minutes
    });

    res.cookie('refreshToken', refreshToken, {
      ...cookieOptions,
      maxAge: rememberMe ? 30 * 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000 // 30 days or 7 days
    });

    // Respond based on request type
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.json({
        success: true,
        message: 'Login successful',
        user: req.session.user,
        tokens: { accessToken, refreshToken }
      });
    } else {
      res.redirect('/dashboard');
    }

  } catch (error) {
    console.error('Login error:', error);
    
    const errorMessage = error.message || 'An error occurred during login';
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(400).json({
        success: false,
        error: errorMessage
      });
    } else {
      res.render('auth/login', {
        title: 'Login',
        error: errorMessage,
        user: null
      });
    }
  }
});

// GET /auth/register - Registration page
router.get('/register', (req, res) => {
  if (req.session.user) {
    return res.redirect('/dashboard');
  }
  
  res.render('auth/register', {
    title: 'Register',
    error: null,
    user: null
  });
});

// POST /auth/register - Register user
router.post('/register', authLimiter, registerValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.render('auth/register', {
        title: 'Register',
        error: errors.array()[0].msg,
        user: null,
        formData: req.body
      });
    }

    const { username, email, password, firstName, lastName, department, location } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      return res.render('auth/register', {
        title: 'Register',
        error: 'User with this email or username already exists',
        user: null,
        formData: req.body
      });
    }

    // Get default user role
    const userRole = await Role.findOne({ name: 'User' });
    
    // Create user
    const user = new User({
      username,
      email,
      password,
      firstName,
      lastName,
      roles: userRole ? [userRole._id] : [],
      attributes: {
        department: department || '',
        location: location || '',
        level: 'user'
      }
    });

    await user.save();

    // Generate email verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    user.emailVerificationToken = verificationToken;
    await user.save();

    // Send verification email
    try {
      await sendEmail({
        to: email,
        subject: 'Verify Your Email Address',
        template: 'email-verification',
        data: {
          name: firstName,
          verificationUrl: `${process.env.BASE_URL || 'http://localhost:3000'}/auth/verify-email?token=${verificationToken}`
        }
      });
    } catch (emailError) {
      console.error('Email sending error:', emailError);
    }

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(201).json({
        success: true,
        message: 'Registration successful. Please check your email for verification.',
        userId: user._id
      });
    } else {
      res.redirect('/auth/login?message=Registration successful. Please check your email for verification.');
    }

  } catch (error) {
    console.error('Registration error:', error);
    
    const errorMessage = error.code === 11000 
      ? 'User with this email or username already exists'
      : 'An error occurred during registration';
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(400).json({
        success: false,
        error: errorMessage
      });
    } else {
      res.render('auth/register', {
        title: 'Register',
        error: errorMessage,
        user: null,
        formData: req.body
      });
    }
  }
});

// GET /auth/verify-email - Verify email address
router.get('/verify-email', async (req, res) => {
  try {
    const { token } = req.query;
    
    if (!token) {
      return res.redirect('/auth/login?error=Invalid verification token');
    }

    const user = await User.findOne({ emailVerificationToken: token });
    
    if (!user) {
      return res.redirect('/auth/login?error=Invalid or expired verification token');
    }

    user.emailVerified = true;
    user.emailVerificationToken = undefined;
    await user.save();

    res.redirect('/auth/login?message=Email verified successfully. You can now login.');

  } catch (error) {
    console.error('Email verification error:', error);
    res.redirect('/auth/login?error=An error occurred during email verification');
  }
});

// GET /auth/forgot-password - Forgot password page
router.get('/forgot-password', (req, res) => {
  res.render('auth/forgot-password', {
    title: 'Forgot Password',
    error: null,
    message: null,
    user: null
  });
});

// POST /auth/forgot-password - Send password reset email
router.post('/forgot-password', resetLimiter, [
  body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.render('auth/forgot-password', {
        title: 'Forgot Password',
        error: errors.array()[0].msg,
        user: null
      });
    }

    const { email } = req.body;
    const user = await User.findOne({ email, isActive: true });

    // Always show success message for security
    const successMessage = 'If an account with that email exists, we have sent a password reset link.';

    if (user) {
      // Generate reset token
      const resetToken = crypto.randomBytes(32).toString('hex');
      user.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
      user.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
      await user.save();

      // Send reset email
      try {
        await sendEmail({
          to: email,
          subject: 'Password Reset Request',
          template: 'password-reset',
          data: {
            name: user.firstName,
            resetUrl: `${process.env.BASE_URL || 'http://localhost:3000'}/auth/reset-password?token=${resetToken}`,
            expiresIn: '10 minutes'
          }
        });
      } catch (emailError) {
        console.error('Password reset email error:', emailError);
      }
    }

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.json({
        success: true,
        message: successMessage
      });
    } else {
      res.render('auth/forgot-password', {
        title: 'Forgot Password',
        message: successMessage,
        user: null
      });
    }

  } catch (error) {
    console.error('Forgot password error:', error);
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(500).json({
        success: false,
        error: 'An error occurred. Please try again.'
      });
    } else {
      res.render('auth/forgot-password', {
        title: 'Forgot Password',
        error: 'An error occurred. Please try again.',
        user: null
      });
    }
  }
});

// GET /auth/reset-password - Reset password page
router.get('/reset-password', async (req, res) => {
  try {
    const { token } = req.query;
    
    if (!token) {
      return res.redirect('/auth/forgot-password?error=Invalid reset token');
    }

    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.redirect('/auth/forgot-password?error=Invalid or expired reset token');
    }

    res.render('auth/reset-password', {
      title: 'Reset Password',
      token,
      error: null,
      user: null
    });

  } catch (error) {
    console.error('Reset password page error:', error);
    res.redirect('/auth/forgot-password?error=An error occurred');
  }
});

// POST /auth/reset-password - Reset password
router.post('/reset-password', [
  body('token').notEmpty().withMessage('Reset token is required'),
  body('password')
    .isLength({ min: 6 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must be at least 6 characters with uppercase, lowercase, and number'),
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords do not match');
      }
      return true;
    })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.render('auth/reset-password', {
        title: 'Reset Password',
        token: req.body.token,
        error: errors.array()[0].msg,
        user: null
      });
    }

    const { token, password } = req.body;
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    
    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.render('auth/reset-password', {
        title: 'Reset Password',
        token,
        error: 'Invalid or expired reset token',
        user: null
      });
    }

    // Update password
    user.password = password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.refreshTokens = []; // Invalidate all refresh tokens
    await user.save();

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.json({
        success: true,
        message: 'Password reset successful. You can now login with your new password.'
      });
    } else {
      res.redirect('/auth/login?message=Password reset successful. You can now login with your new password.');
    }

  } catch (error) {
    console.error('Reset password error:', error);
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(500).json({
        success: false,
        error: 'An error occurred. Please try again.'
      });
    } else {
      res.render('auth/reset-password', {
        title: 'Reset Password',
        token: req.body.token || '',
        error: 'An error occurred. Please try again.',
        user: null
      });
    }
  }
});

// POST /auth/refresh-token - Refresh access token
router.post('/refresh-token', async (req, res) => {
  try {
    const { refreshToken } = req.cookies || req.body;
    
    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        error: 'Refresh token not provided'
      });
    }

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET || 'your-refresh-secret');
    
    // Find user and check if refresh token exists and is active
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Invalid refresh token'
      });
    }

    const tokenData = user.refreshTokens.find(t => t.token === refreshToken && t.isActive);
    if (!tokenData || tokenData.expiresAt < new Date()) {
      return res.status(401).json({
        success: false,
        error: 'Refresh token expired or invalid'
      });
    }

    // Generate new access token
    const newAccessToken = user.generateAccessToken();

    res.cookie('accessToken', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000 // 15 minutes
    });

    res.json({
      success: true,
      accessToken: newAccessToken
    });

  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(401).json({
      success: false,
      error: 'Invalid refresh token'
    });
  }
});

// POST /auth/logout - Logout user
router.post('/logout', async (req, res) => {
  try {
    const { refreshToken } = req.cookies;
    
    // Invalidate refresh token if exists
    if (refreshToken && req.session.user) {
      const user = await User.findById(req.session.user.id);
      if (user) {
        user.refreshTokens = user.refreshTokens.filter(t => t.token !== refreshToken);
        await user.save();
      }
    }

    // Clear session and cookies
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destruction error:', err);
      }
    });

    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    res.clearCookie('connect.sid');

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.json({
        success: true,
        message: 'Logout successful'
      });
    } else {
      res.redirect('/auth/login?message=You have been logged out successfully');
    }

  } catch (error) {
    console.error('Logout error:', error);
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(500).json({
        success: false,
        error: 'An error occurred during logout'
      });
    } else {
      res.redirect('/auth/login');
    }
  }
});

// GET /auth/profile - User profile page
router.get('/profile', async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/auth/login');
  }

  try {
    const user = await User.findById(req.session.user.id).populate('roles');
    
    if (!user) {
      return res.redirect('/auth/login?error=User not found');
    }

    res.render('auth/profile', {
      title: 'Profile',
      user: req.session.user,
      userData: user,
      error: req.query.error,
      message: req.query.message
    });

  } catch (error) {
    console.error('Profile page error:', error);
    res.redirect('/dashboard?error=An error occurred loading your profile');
  }
});

// POST /auth/profile - Update user profile
router.post('/profile', [
  body('firstName').isLength({ min: 1, max: 50 }).trim(),
  body('lastName').isLength({ min: 1, max: 50 }).trim(),
  body('email').isEmail().normalizeEmail()
], async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/auth/login');
  }

  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.redirect(`/auth/profile?error=${encodeURIComponent(errors.array()[0].msg)}`);
    }

    const { firstName, lastName, email, department, location } = req.body;
    
    const user = await User.findById(req.session.user.id);
    if (!user) {
      return res.redirect('/auth/login?error=User not found');
    }

    // Check if email is already taken by another user
    if (email !== user.email) {
      const existingUser = await User.findOne({ email, _id: { $ne: user._id } });
      if (existingUser) {
        return res.redirect('/auth/profile?error=Email is already taken');
      }
    }

    // Update user data
    user.firstName = firstName;
    user.lastName = lastName;
    user.email = email;
    user.attributes.department = department || '';
    user.attributes.location = location || '';
    
    await user.save();

    // Update session data
    req.session.user.email = email;
    req.session.user.fullName = `${firstName} ${lastName}`;
    req.session.user.attributes = user.attributes;

    res.redirect('/auth/profile?message=Profile updated successfully');

  } catch (error) {
    console.error('Profile update error:', error);
    res.redirect('/auth/profile?error=An error occurred updating your profile');
  }
});

// POST /auth/change-password - Change password
router.post('/change-password', [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword')
    .isLength({ min: 6 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('New password must be at least 6 characters with uppercase, lowercase, and number'),
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.newPassword) {
        throw new Error('Passwords do not match');
      }
      return true;
    })
], async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({
      success: false,
      error: 'Not authenticated'
    });
  }

  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const { currentPassword, newPassword } = req.body;
    
    const user = await User.findById(req.session.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Verify current password
    const isValidPassword = await user.comparePassword(currentPassword);
    if (!isValidPassword) {
      return res.status(400).json({
        success: false,
        error: 'Current password is incorrect'
      });
    }

    // Update password
    user.password = newPassword;
    user.refreshTokens = []; // Invalidate all refresh tokens
    await user.save();

    res.json({
      success: true,
      message: 'Password changed successfully'
    });

  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({
      success: false,
      error: 'An error occurred changing your password'
    });
  }
});

module.exports = router;
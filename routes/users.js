// routes/users.js - User management routes
const express = require('express');
const { body, validationResult } = require('express-validator');
const { requireAuth, requirePermission, requireRole } = require('../middleware/auth');
const User = require('../models/User');
const Role = require('../models/Role');

const router = express.Router();

// All routes require authentication
router.use(requireAuth);

// GET /users - List users (with pagination and search)
router.get('/', requirePermission('users', 'read'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    const search = req.query.search || '';
    const role = req.query.role || '';
    const department = req.query.department || '';
    const status = req.query.status || '';

    // Build query
    const query = {};
    
    if (search) {
      query.$or = [
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { username: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }

    if (role) {
      query.roles = role;
    }

    if (department) {
      query['attributes.department'] = department;
    }

    if (status) {
      query.isActive = status === 'active';
    }

    // Get users with pagination
    const users = await User.find(query)
      .populate('roles', 'name')
      .select('-password -refreshTokens')
      .sort({ createdAt: -1 })
      .limit(limit)
      .skip(skip);

    const total = await User.countDocuments(query);
    const totalPages = Math.ceil(total / limit);

    // Get all roles for filter dropdown
    const roles = await Role.find({ isActive: true }).select('name');

    // Get unique departments
    const departments = await User.distinct('attributes.department', { 'attributes.department': { $ne: '' } });

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.json({
        success: true,
        users,
        pagination: {
          page,
          limit,
          total,
          totalPages,
          hasNext: page < totalPages,
          hasPrev: page > 1
        }
      });
    } else {
      res.render('admin/users/index', {
        title: 'User Management',
        currentPage: 'users',
        users,
        roles,
        departments,
        pagination: {
          page,
          limit,
          total,
          totalPages,
          hasNext: page < totalPages,
          hasPrev: page > 1
        },
        filters: { search, role, department, status },
        user: req.session.user
      });
    }

  } catch (error) {
    console.error('Error listing users:', error);
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(500).json({
        success: false,
        error: 'Failed to load users'
      });
    } else {
      res.render('admin/users/index', {
        title: 'User Management',
        currentPage: 'users',
        users: [],
        roles: [],
        departments: [],
        pagination: {},
        filters: {},
        error: 'Failed to load users',
        user: req.session.user
      });
    }
  }
});

// GET /users/new - Create user form
router.get('/new', requirePermission('users', 'create'), async (req, res) => {
  try {
    const roles = await Role.find({ isActive: true });
    
    res.render('admin/users/form', {
      title: 'Create User',
      currentPage: 'users',
      userData: {},
      roles,
      isEdit: false,
      user: req.session.user
    });

  } catch (error) {
    console.error('Error loading create user form:', error);
    res.redirect('/users?error=Failed to load create form');
  }
});

// POST /users - Create new user
router.post('/', requirePermission('users', 'create'), [
  body('username').isLength({ min: 3, max: 50 }).matches(/^[a-zA-Z0-9_]+$/),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/),
  body('firstName').isLength({ min: 1, max: 50 }).trim(),
  body('lastName').isLength({ min: 1, max: 50 }).trim(),
  body('roles').isArray().withMessage('At least one role is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      if (req.xhr || req.headers.accept?.includes('application/json')) {
        return res.status(400).json({
          success: false,
          error: errors.array()[0].msg
        });
      } else {
        const roles = await Role.find({ isActive: true });
        return res.render('admin/users/form', {
          title: 'Create User',
          currentPage: 'users',
          userData: req.body,
          roles,
          isEdit: false,
          error: errors.array()[0].msg,
          user: req.session.user
        });
      }
    }

    const { username, email, password, firstName, lastName, roles, department, location } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      const errorMsg = 'User with this email or username already exists';
      
      if (req.xhr || req.headers.accept?.includes('application/json')) {
        return res.status(400).json({
          success: false,
          error: errorMsg
        });
      } else {
        const rolesData = await Role.find({ isActive: true });
        return res.render('admin/users/form', {
          title: 'Create User',
          currentPage: 'users',
          userData: req.body,
          roles: rolesData,
          isEdit: false,
          error: errorMsg,
          user: req.session.user
        });
      }
    }

    // Create user
    const user = new User({
      username,
      email,
      password,
      firstName,
      lastName,
      roles: roles || [],
      attributes: {
        department: department || '',
        location: location || '',
        level: 'user'
      },
      emailVerified: true, // Admin created users are pre-verified
      isActive: true
    });

    await user.save();

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(201).json({
        success: true,
        message: 'User created successfully',
        userId: user._id
      });
    } else {
      res.redirect('/users?message=User created successfully');
    }

  } catch (error) {
    console.error('Error creating user:', error);
    
    const errorMsg = error.code === 11000 
      ? 'User with this email or username already exists'
      : 'Failed to create user';
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(500).json({
        success: false,
        error: errorMsg
      });
    } else {
      const roles = await Role.find({ isActive: true });
      res.render('admin/users/form', {
        title: 'Create User',
        currentPage: 'users',
        userData: req.body,
        roles,
        isEdit: false,
        error: errorMsg,
        user: req.session.user
      });
    }
  }
});

// GET /users/:id - View user details
router.get('/:id', requirePermission('users', 'read'), async (req, res) => {
  try {
    const userData = await User.findById(req.params.id)
      .populate('roles')
      .populate('attributes.manager', 'firstName lastName username')
      .select('-password -refreshTokens');

    if (!userData) {
      if (req.xhr || req.headers.accept?.includes('application/json')) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      } else {
        return res.redirect('/users?error=User not found');
      }
    }

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.json({
        success: true,
        user: userData
      });
    } else {
      res.render('admin/users/view', {
        title: `User: ${userData.fullName}`,
        currentPage: 'users',
        userData,
        user: req.session.user
      });
    }

  } catch (error) {
    console.error('Error viewing user:', error);
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(500).json({
        success: false,
        error: 'Failed to load user'
      });
    } else {
      res.redirect('/users?error=Failed to load user');
    }
  }
});

// GET /users/:id/edit - Edit user form
router.get('/:id/edit', requirePermission('users', 'update'), async (req, res) => {
  try {
    const userData = await User.findById(req.params.id)
      .populate('roles')
      .select('-password -refreshTokens');

    if (!userData) {
      return res.redirect('/users?error=User not found');
    }

    const roles = await Role.find({ isActive: true });
    
    res.render('admin/users/form', {
      title: `Edit User: ${userData.fullName}`,
      currentPage: 'users',
      userData,
      roles,
      isEdit: true,
      user: req.session.user
    });

  } catch (error) {
    console.error('Error loading edit user form:', error);
    res.redirect('/users?error=Failed to load edit form');
  }
});

// PUT /users/:id - Update user
router.put('/:id', requirePermission('users', 'update'), [
  body('username').isLength({ min: 3, max: 50 }).matches(/^[a-zA-Z0-9_]+$/),
  body('email').isEmail().normalizeEmail(),
  body('firstName').isLength({ min: 1, max: 50 }).trim(),
  body('lastName').isLength({ min: 1, max: 50 }).trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const userData = await User.findById(req.params.id);
    if (!userData) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    const { username, email, firstName, lastName, roles, department, location, isActive } = req.body;

    // Check if email/username is taken by another user
    const existingUser = await User.findOne({
      $or: [{ email }, { username }],
      _id: { $ne: req.params.id }
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: 'Email or username is already taken'
      });
    }

    // Update user data
    userData.username = username;
    userData.email = email;
    userData.firstName = firstName;
    userData.lastName = lastName;
    userData.roles = roles || [];
    userData.attributes.department = department || '';
    userData.attributes.location = location || '';
    userData.isActive = isActive !== undefined ? isActive : userData.isActive;

    await userData.save();

    res.json({
      success: true,
      message: 'User updated successfully'
    });

  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update user'
    });
  }
});

// DELETE /users/:id - Delete user
router.delete('/:id', requirePermission('users', 'delete'), async (req, res) => {
  try {
    const userData = await User.findById(req.params.id);
    
    if (!userData) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Prevent deletion of super admin
    await userData.populate('roles');
    const isSuperAdmin = userData.roles.some(role => role.name === 'Super Admin');
    
    if (isSuperAdmin) {
      return res.status(403).json({
        success: false,
        error: 'Cannot delete Super Admin user'
      });
    }

    // Soft delete by deactivating
    userData.isActive = false;
    userData.email = `deleted_${Date.now()}_${userData.email}`;
    userData.username = `deleted_${Date.now()}_${userData.username}`;
    await userData.save();

    res.json({
      success: true,
      message: 'User deleted successfully'
    });

  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete user'
    });
  }
});

// POST /users/:id/toggle-status - Toggle user active status
router.post('/:id/toggle-status', requirePermission('users', 'update'), async (req, res) => {
  try {
    const userData = await User.findById(req.params.id).populate('roles');
    
    if (!userData) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Prevent deactivating super admin
    const isSuperAdmin = userData.roles.some(role => role.name === 'Super Admin');
    
    if (isSuperAdmin && userData.isActive) {
      return res.status(403).json({
        success: false,
        error: 'Cannot deactivate Super Admin user'
      });
    }

    userData.isActive = !userData.isActive;
    await userData.save();

    res.json({
      success: true,
      message: `User ${userData.isActive ? 'activated' : 'deactivated'} successfully`,
      isActive: userData.isActive
    });

  } catch (error) {
    console.error('Error toggling user status:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to toggle user status'
    });
  }
});

// POST /users/:id/reset-password - Reset user password
router.post('/:id/reset-password', requirePermission('users', 'update'), async (req, res) => {
  try {
    const userData = await User.findById(req.params.id);
    
    if (!userData) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Generate temporary password
    const tempPassword = Math.random().toString(36).slice(-8) + 'A1!';
    userData.password = tempPassword;
    userData.refreshTokens = []; // Invalidate all sessions
    await userData.save();

    res.json({
      success: true,
      message: 'Password reset successfully',
      tempPassword: tempPassword
    });

  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to reset password'
    });
  }
});

module.exports = router;
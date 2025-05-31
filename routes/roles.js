// routes/roles.js - Role management routes
const express = require('express');
const { body, validationResult } = require('express-validator');
const { requireAuth, requirePermission } = require('../middleware/auth');
const Role = require('../models/Role');
const User = require('../models/User');

const router = express.Router();

// All routes require authentication
router.use(requireAuth);

// GET /roles - List roles
router.get('/', requirePermission('roles', 'read'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    const search = req.query.search || '';

    // Build query
    const query = {};
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    // Get roles with pagination
    const roles = await Role.find(query)
      .populate('parentRoles', 'name')
      .populate('createdBy', 'firstName lastName username')
      .sort({ 'attributes.level': -1, createdAt: -1 })
      .limit(limit)
      .skip(skip);

    const total = await Role.countDocuments(query);
    const totalPages = Math.ceil(total / limit);

    // Get user count for each role
    const rolesWithCounts = await Promise.all(
      roles.map(async (role) => {
        const userCount = await User.countDocuments({ roles: role._id, isActive: true });
        return {
          ...role.toObject(),
          userCount
        };
      })
    );

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.json({
        success: true,
        roles: rolesWithCounts,
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
      res.render('admin/roles/index', {
        title: 'Role Management',
        currentPage: 'roles',
        roles: rolesWithCounts,
        pagination: {
          page,
          limit,
          total,
          totalPages,
          hasNext: page < totalPages,
          hasPrev: page > 1
        },
        filters: { search },
        user: req.session.user
      });
    }

  } catch (error) {
    console.error('Error listing roles:', error);
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(500).json({
        success: false,
        error: 'Failed to load roles'
      });
    } else {
      res.render('admin/roles/index', {
        title: 'Role Management',
        currentPage: 'roles',
        roles: [],
        pagination: {},
        filters: {},
        error: 'Failed to load roles',
        user: req.session.user
      });
    }
  }
});

// GET /roles/new - Create role form
router.get('/new', requirePermission('roles', 'create'), async (req, res) => {
  try {
    const parentRoles = await Role.find({ isActive: true }).select('name');
    
    res.render('admin/roles/form', {
      title: 'Create Role',
      currentPage: 'roles',
      roleData: {},
      parentRoles,
      isEdit: false,
      user: req.session.user
    });

  } catch (error) {
    console.error('Error loading create role form:', error);
    res.redirect('/roles?error=Failed to load create form');
  }
});

// POST /roles - Create new role
router.post('/', requirePermission('roles', 'create'), [
  body('name').isLength({ min: 2, max: 50 }).trim(),
  body('description').optional().isLength({ max: 500 }).trim()
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
        const parentRoles = await Role.find({ isActive: true }).select('name');
        return res.render('admin/roles/form', {
          title: 'Create Role',
          currentPage: 'roles',
          roleData: req.body,
          parentRoles,
          isEdit: false,
          error: errors.array()[0].msg,
          user: req.session.user
        });
      }
    }

    const { name, description, parentRoles, level, scope } = req.body;

    // Check if role already exists
    const existingRole = await Role.findOne({ name });
    if (existingRole) {
      const errorMsg = 'Role with this name already exists';
      
      if (req.xhr || req.headers.accept?.includes('application/json')) {
        return res.status(400).json({
          success: false,
          error: errorMsg
        });
      } else {
        const parentRolesData = await Role.find({ isActive: true }).select('name');
        return res.render('admin/roles/form', {
          title: 'Create Role',
          currentPage: 'roles',
          roleData: req.body,
          parentRoles: parentRolesData,
          isEdit: false,
          error: errorMsg,
          user: req.session.user
        });
      }
    }

    // Create role
    const role = new Role({
      name,
      description,
      parentRoles: parentRoles || [],
      attributes: {
        level: parseInt(level) || 1,
        scope: scope || 'personal'
      },
      createdBy: req.user._id,
      isActive: true
    });

    await role.save();

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(201).json({
        success: true,
        message: 'Role created successfully',
        roleId: role._id
      });
    } else {
      res.redirect('/roles?message=Role created successfully');
    }

  } catch (error) {
    console.error('Error creating role:', error);
    
    const errorMsg = 'Failed to create role';
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(500).json({
        success: false,
        error: errorMsg
      });
    } else {
      const parentRoles = await Role.find({ isActive: true }).select('name');
      res.render('admin/roles/form', {
        title: 'Create Role',
        currentPage: 'roles',
        roleData: req.body,
        parentRoles,
        isEdit: false,
        error: errorMsg,
        user: req.session.user
      });
    }
  }
});

// GET /roles/:id - View role details
router.get('/:id', requirePermission('roles', 'read'), async (req, res) => {
  try {
    const roleData = await Role.findById(req.params.id)
      .populate('parentRoles', 'name')
      .populate('createdBy', 'firstName lastName username');

    if (!roleData) {
      if (req.xhr || req.headers.accept?.includes('application/json')) {
        return res.status(404).json({
          success: false,
          error: 'Role not found'
        });
      } else {
        return res.redirect('/roles?error=Role not found');
      }
    }

    // Get users with this role
    const users = await User.find({ roles: roleData._id, isActive: true })
      .select('firstName lastName username email')
      .limit(10);

    const userCount = await User.countDocuments({ roles: roleData._id, isActive: true });

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.json({
        success: true,
        role: roleData,
        users,
        userCount
      });
    } else {
      res.render('admin/roles/view', {
        title: `Role: ${roleData.name}`,
        currentPage: 'roles',
        roleData,
        users,
        userCount,
        user: req.session.user
      });
    }

  } catch (error) {
    console.error('Error viewing role:', error);
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(500).json({
        success: false,
        error: 'Failed to load role'
      });
    } else {
      res.redirect('/roles?error=Failed to load role');
    }
  }
});

// GET /roles/:id/edit - Edit role form
router.get('/:id/edit', requirePermission('roles', 'update'), async (req, res) => {
  try {
    const roleData = await Role.findById(req.params.id).populate('parentRoles');

    if (!roleData) {
      return res.redirect('/roles?error=Role not found');
    }

    // Prevent editing system roles
    if (roleData.isSystemRole) {
      return res.redirect('/roles?error=Cannot edit system roles');
    }

    const parentRoles = await Role.find({ 
      isActive: true, 
      _id: { $ne: req.params.id } // Exclude self
    }).select('name');
    
    res.render('admin/roles/form', {
      title: `Edit Role: ${roleData.name}`,
      currentPage: 'roles',
      roleData,
      parentRoles,
      isEdit: true,
      user: req.session.user
    });

  } catch (error) {
    console.error('Error loading edit role form:', error);
    res.redirect('/roles?error=Failed to load edit form');
  }
});

// PUT /roles/:id - Update role
router.put('/:id', requirePermission('roles', 'update'), [
  body('name').isLength({ min: 2, max: 50 }).trim(),
  body('description').optional().isLength({ max: 500 }).trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const roleData = await Role.findById(req.params.id);
    if (!roleData) {
      return res.status(404).json({
        success: false,
        error: 'Role not found'
      });
    }

    // Prevent editing system roles
    if (roleData.isSystemRole) {
      return res.status(403).json({
        success: false,
        error: 'Cannot edit system roles'
      });
    }

    const { name, description, parentRoles, level, scope, isActive } = req.body;

    // Check if name is taken by another role
    const existingRole = await Role.findOne({
      name,
      _id: { $ne: req.params.id }
    });

    if (existingRole) {
      return res.status(400).json({
        success: false,
        error: 'Role name is already taken'
      });
    }

    // Update role data
    roleData.name = name;
    roleData.description = description;
    roleData.parentRoles = parentRoles || [];
    roleData.attributes.level = parseInt(level) || roleData.attributes.level;
    roleData.attributes.scope = scope || roleData.attributes.scope;
    roleData.isActive = isActive !== undefined ? isActive : roleData.isActive;
    roleData.updatedBy = req.user._id;

    await roleData.save();

    res.json({
      success: true,
      message: 'Role updated successfully'
    });

  } catch (error) {
    console.error('Error updating role:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update role'
    });
  }
});

// DELETE /roles/:id - Delete role
router.delete('/:id', requirePermission('roles', 'delete'), async (req, res) => {
  try {
    const roleData = await Role.findById(req.params.id);
    
    if (!roleData) {
      return res.status(404).json({
        success: false,
        error: 'Role not found'
      });
    }

    // Prevent deletion of system roles
    if (roleData.isSystemRole) {
      return res.status(403).json({
        success: false,
        error: 'Cannot delete system roles'
      });
    }

    // Check if role is assigned to users
    const userCount = await User.countDocuments({ roles: roleData._id });
    
    if (userCount > 0) {
      return res.status(400).json({
        success: false,
        error: `Cannot delete role. It is assigned to ${userCount} user(s)`
      });
    }

    await roleData.deleteOne();

    res.json({
      success: true,
      message: 'Role deleted successfully'
    });

  } catch (error) {
    console.error('Error deleting role:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete role'
    });
  }
});

// GET /roles/:id/permissions - Get role permissions
router.get('/:id/permissions', requirePermission('roles', 'read'), async (req, res) => {
  try {
    const roleData = await Role.findById(req.params.id);
    
    if (!roleData) {
      return res.status(404).json({
        success: false,
        error: 'Role not found'
      });
    }

    res.json({
      success: true,
      permissions: roleData.permissions,
      effectivePermissions: roleData.effectivePermissions
    });

  } catch (error) {
    console.error('Error getting role permissions:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get permissions'
    });
  }
});

// PUT /roles/:id/permissions - Update role permissions
router.put('/:id/permissions', requirePermission('roles', 'update'), async (req, res) => {
  try {
    const roleData = await Role.findById(req.params.id);
    
    if (!roleData) {
      return res.status(404).json({
        success: false,
        error: 'Role not found'
      });
    }

    const { resource, actions, conditions, fields } = req.body;

    if (!resource || !actions || !Array.isArray(actions)) {
      return res.status(400).json({
        success: false,
        error: 'Resource and actions are required'
      });
    }

    await roleData.addPermission(resource, actions, conditions || {}, fields || []);

    res.json({
      success: true,
      message: 'Permissions updated successfully'
    });

  } catch (error) {
    console.error('Error updating role permissions:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update permissions'
    });
  }
});

// DELETE /roles/:id/permissions/:resource - Remove role permission
router.delete('/:id/permissions/:resource', requirePermission('roles', 'update'), async (req, res) => {
  try {
    const roleData = await Role.findById(req.params.id);
    
    if (!roleData) {
      return res.status(404).json({
        success: false,
        error: 'Role not found'
      });
    }

    const { resource } = req.params;
    const { action } = req.query;

    await roleData.removePermission(resource, action);

    res.json({
      success: true,
      message: 'Permission removed successfully'
    });

  } catch (error) {
    console.error('Error removing role permission:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to remove permission'
    });
  }
});

// GET /roles/:id/users - Get users with this role
router.get('/:id/users', requirePermission('roles', 'read'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const roleData = await Role.findById(req.params.id);
    
    if (!roleData) {
      return res.status(404).json({
        success: false,
        error: 'Role not found'
      });
    }

    const users = await User.find({ roles: roleData._id, isActive: true })
      .select('firstName lastName username email attributes.department attributes.location')
      .sort({ createdAt: -1 })
      .limit(limit)
      .skip(skip);

    const total = await User.countDocuments({ roles: roleData._id, isActive: true });
    const totalPages = Math.ceil(total / limit);

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

  } catch (error) {
    console.error('Error getting role users:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get users'
    });
  }
});

module.exports = router;
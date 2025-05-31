// routes/permissions.js - Permission management routes
const express = require('express');
const { requireAuth, requirePermission } = require('../middleware/auth');
const Role = require('../models/Role');
const DynamicModel = require('../models/DynamicModel');

const router = express.Router();

// All routes require authentication
router.use(requireAuth);

// GET /permissions - Permission management dashboard
router.get('/', requirePermission('permissions', 'read'), async (req, res) => {
  try {
    // Get all roles with their permissions
    const roles = await Role.find({ isActive: true })
      .populate('parentRoles', 'name')
      .sort({ 'attributes.level': -1 });

    // Get all dynamic models for resource management
    const models = await DynamicModel.find({ isActive: true })
      .select('name displayName description');

    // Define standard resources
    const standardResources = [
      { name: 'users', displayName: 'Users', description: 'User management' },
      { name: 'roles', displayName: 'Roles', description: 'Role management' },
      { name: 'permissions', displayName: 'Permissions', description: 'Permission management' },
      { name: 'attachments', displayName: 'Files', description: 'File management' },
      { name: 'system', displayName: 'System', description: 'System administration' }
    ];

    // Available actions
    const actions = ['create', 'read', 'update', 'delete', 'execute'];

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.json({
        success: true,
        roles,
        models,
        standardResources,
        actions
      });
    } else {
      res.render('admin/permissions/index', {
        title: 'Permission Management',
        currentPage: 'permissions',
        roles,
        models,
        standardResources,
        actions,
        user: req.session.user
      });
    }

  } catch (error) {
    console.error('Error loading permissions dashboard:', error);
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(500).json({
        success: false,
        error: 'Failed to load permissions'
      });
    } else {
      res.render('admin/permissions/index', {
        title: 'Permission Management',
        currentPage: 'permissions',
        roles: [],
        models: [],
        standardResources: [],
        actions: [],
        error: 'Failed to load permissions',
        user: req.session.user
      });
    }
  }
});

// GET /permissions/matrix - Permission matrix view
router.get('/matrix', requirePermission('permissions', 'read'), async (req, res) => {
  try {
    const roles = await Role.find({ isActive: true })
      .populate('parentRoles', 'name')
      .sort({ 'attributes.level': -1 });

    const models = await DynamicModel.find({ isActive: true })
      .select('name displayName');

    // Create permission matrix
    const matrix = {};
    const allResources = [
      'users', 'roles', 'permissions', 'attachments', 'system',
      ...models.map(m => m.name.toLowerCase())
    ];

    roles.forEach(role => {
      matrix[role.name] = {};
      
      allResources.forEach(resource => {
        matrix[role.name][resource] = {
          create: role.hasPermission(resource, 'create'),
          read: role.hasPermission(resource, 'read'),
          update: role.hasPermission(resource, 'update'),
          delete: role.hasPermission(resource, 'delete'),
          execute: role.hasPermission(resource, 'execute')
        };
      });
    });

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.json({
        success: true,
        matrix,
        roles: roles.map(r => ({ id: r._id, name: r.name })),
        resources: allResources
      });
    } else {
      res.render('admin/permissions/matrix', {
        title: 'Permission Matrix',
        currentPage: 'permissions',
        matrix,
        roles,
        resources: allResources,
        user: req.session.user
      });
    }

  } catch (error) {
    console.error('Error loading permission matrix:', error);
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(500).json({
        success: false,
        error: 'Failed to load permission matrix'
      });
    } else {
      res.render('admin/permissions/matrix', {
        title: 'Permission Matrix',
        currentPage: 'permissions',
        matrix: {},
        roles: [],
        resources: [],
        error: 'Failed to load permission matrix',
        user: req.session.user
      });
    }
  }
});

// POST /permissions/assign - Assign permission to role
router.post('/assign', requirePermission('permissions', 'update'), async (req, res) => {
  try {
    const { roleId, resource, actions, conditions, fields } = req.body;

    if (!roleId || !resource || !actions || !Array.isArray(actions)) {
      return res.status(400).json({
        success: false,
        error: 'Role ID, resource, and actions are required'
      });
    }

    const role = await Role.findById(roleId);
    if (!role) {
      return res.status(404).json({
        success: false,
        error: 'Role not found'
      });
    }

    // Prevent modifying system roles' core permissions
    if (role.isSystemRole && ['users', 'roles', 'permissions'].includes(resource)) {
      return res.status(403).json({
        success: false,
        error: 'Cannot modify core permissions of system roles'
      });
    }

    await role.addPermission(resource, actions, conditions || {}, fields || []);

    res.json({
      success: true,
      message: 'Permission assigned successfully'
    });

  } catch (error) {
    console.error('Error assigning permission:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to assign permission'
    });
  }
});

// DELETE /permissions/revoke - Revoke permission from role
router.delete('/revoke', requirePermission('permissions', 'update'), async (req, res) => {
  try {
    const { roleId, resource, action } = req.body;

    if (!roleId || !resource) {
      return res.status(400).json({
        success: false,
        error: 'Role ID and resource are required'
      });
    }

    const role = await Role.findById(roleId);
    if (!role) {
      return res.status(404).json({
        success: false,
        error: 'Role not found'
      });
    }

    // Prevent modifying system roles' core permissions
    if (role.isSystemRole && ['users', 'roles', 'permissions'].includes(resource)) {
      return res.status(403).json({
        success: false,
        error: 'Cannot modify core permissions of system roles'
      });
    }

    await role.removePermission(resource, action);

    res.json({
      success: true,
      message: 'Permission revoked successfully'
    });

  } catch (error) {
    console.error('Error revoking permission:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to revoke permission'
    });
  }
});

// POST /permissions/bulk-assign - Bulk assign permissions
router.post('/bulk-assign', requirePermission('permissions', 'update'), async (req, res) => {
  try {
    const { assignments } = req.body; // Array of { roleId, resource, actions, conditions }

    if (!assignments || !Array.isArray(assignments)) {
      return res.status(400).json({
        success: false,
        error: 'Assignments array is required'
      });
    }

    const results = [];
    
    for (const assignment of assignments) {
      try {
        const { roleId, resource, actions, conditions, fields } = assignment;
        
        const role = await Role.findById(roleId);
        if (!role) {
          results.push({
            roleId,
            resource,
            success: false,
            error: 'Role not found'
          });
          continue;
        }

        // Check system role restrictions
        if (role.isSystemRole && ['users', 'roles', 'permissions'].includes(resource)) {
          results.push({
            roleId,
            resource,
            success: false,
            error: 'Cannot modify core permissions of system roles'
          });
          continue;
        }

        await role.addPermission(resource, actions, conditions || {}, fields || []);
        
        results.push({
          roleId,
          resource,
          success: true,
          message: 'Permission assigned successfully'
        });

      } catch (error) {
        results.push({
          roleId: assignment.roleId,
          resource: assignment.resource,
          success: false,
          error: error.message
        });
      }
    }

    const successCount = results.filter(r => r.success).length;
    const failureCount = results.filter(r => !r.success).length;

    res.json({
      success: failureCount === 0,
      message: `${successCount} permissions assigned successfully${failureCount > 0 ? `, ${failureCount} failed` : ''}`,
      results
    });

  } catch (error) {
    console.error('Error bulk assigning permissions:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to bulk assign permissions'
    });
  }
});

// GET /permissions/check - Check if user has permission
router.get('/check', requireAuth, async (req, res) => {
  try {
    const { resource, action, context } = req.query;

    if (!resource || !action) {
      return res.status(400).json({
        success: false,
        error: 'Resource and action are required'
      });
    }

    const hasPermission = await req.user.hasPermission(
      resource, 
      action, 
      context ? JSON.parse(context) : {}
    );

    res.json({
      success: true,
      hasPermission,
      user: {
        id: req.user._id,
        username: req.user.username,
        roles: req.user.roles
      }
    });

  } catch (error) {
    console.error('Error checking permission:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to check permission'
    });
  }
});

// GET /permissions/resources - Get available resources
router.get('/resources', requirePermission('permissions', 'read'), async (req, res) => {
  try {
    // Standard system resources
    const systemResources = [
      {
        name: 'users',
        displayName: 'Users',
        description: 'User management',
        category: 'system',
        actions: ['create', 'read', 'update', 'delete']
      },
      {
        name: 'roles',
        displayName: 'Roles',
        description: 'Role management',
        category: 'system',
        actions: ['create', 'read', 'update', 'delete']
      },
      {
        name: 'permissions',
        displayName: 'Permissions',
        description: 'Permission management',
        category: 'system',
        actions: ['read', 'update']
      },
      {
        name: 'attachments',
        displayName: 'Files',
        description: 'File management',
        category: 'system',
        actions: ['create', 'read', 'update', 'delete']
      },
      {
        name: 'system',
        displayName: 'System',
        description: 'System administration',
        category: 'system',
        actions: ['read', 'execute']
      }
    ];

    // Dynamic model resources
    const models = await DynamicModel.find({ isActive: true })
      .select('name displayName description');

    const modelResources = models.map(model => ({
      name: model.name.toLowerCase(),
      displayName: model.displayName,
      description: model.description,
      category: 'model',
      actions: ['create', 'read', 'update', 'delete'],
      modelId: model._id
    }));

    const allResources = [...systemResources, ...modelResources];

    res.json({
      success: true,
      resources: allResources,
      categories: [
        { name: 'system', displayName: 'System Resources' },
        { name: 'model', displayName: 'Dynamic Models' }
      ]
    });

  } catch (error) {
    console.error('Error getting resources:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get resources'
    });
  }
});

// GET /permissions/actions - Get available actions
router.get('/actions', requirePermission('permissions', 'read'), async (req, res) => {
  try {
    const actions = [
      {
        name: 'create',
        displayName: 'Create',
        description: 'Create new records'
      },
      {
        name: 'read',
        displayName: 'Read',
        description: 'View and list records'
      },
      {
        name: 'update',
        displayName: 'Update',
        description: 'Modify existing records'
      },
      {
        name: 'delete',
        displayName: 'Delete',
        description: 'Remove records'
      },
      {
        name: 'execute',
        displayName: 'Execute',
        description: 'Execute special operations'
      }
    ];

    res.json({
      success: true,
      actions
    });

  } catch (error) {
    console.error('Error getting actions:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get actions'
    });
  }
});

// POST /permissions/test - Test permission conditions
router.post('/test', requirePermission('permissions', 'read'), async (req, res) => {
  try {
    const { conditions, userAttributes } = req.body;

    if (!conditions || !userAttributes) {
      return res.status(400).json({
        success: false,
        error: 'Conditions and user attributes are required'
      });
    }

    // Create a mock user object for testing
    const mockUser = {
      attributes: userAttributes
    };

    // Import the evaluation function
    const { evaluateConditions } = require('../middleware/auth');
    const result = evaluateConditions(conditions, mockUser);

    res.json({
      success: true,
      conditionsMet: result,
      conditions,
      userAttributes
    });

  } catch (error) {
    console.error('Error testing permission conditions:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to test conditions'
    });
  }
});

module.exports = router;
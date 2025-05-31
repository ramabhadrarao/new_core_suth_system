// routes/dashboard.js - Dashboard and main application routes
const express = require('express');
const { requireAuth, requirePermission } = require('../middleware/auth');
const User = require('../models/User');
const Role = require('../models/Role');
const DynamicModel = require('../models/DynamicModel');
const Attachment = require('../models/Attachment');

const router = express.Router();

// All dashboard routes require authentication
router.use(requireAuth);

// GET /dashboard - Main dashboard
router.get('/', async (req, res) => {
  try {
    // Get dashboard statistics
    const stats = await getDashboardStats(req.user);
    
    // Get recent activities
    const recentActivities = await getRecentActivities(req.user);
    
    // Get user's recent files
    const recentFiles = await Attachment.getUserFiles(req.user._id, { limit: 5 });
    
    // Get available models user can access
    const availableModels = await getAvailableModels(req.user);

    res.render('dashboard/index', {
      title: 'Dashboard',
      user: req.session.user,
      stats,
      recentActivities,
      recentFiles,
      availableModels,
      error: req.query.error,
      message: req.query.message
    });

  } catch (error) {
    console.error('Dashboard error:', error);
    res.render('dashboard/index', {
      title: 'Dashboard',
      user: req.session.user,
      stats: {},
      recentActivities: [],
      recentFiles: [],
      availableModels: [],
      error: 'An error occurred loading the dashboard'
    });
  }
});

// GET /dashboard/stats - Dashboard statistics API
router.get('/stats', async (req, res) => {
  try {
    const stats = await getDashboardStats(req.user);
    res.json({
      success: true,
      stats
    });
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to load dashboard statistics'
    });
  }
});

// GET /dashboard/activities - Recent activities API
router.get('/activities', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const activities = await getRecentActivities(req.user, { skip, limit });
    
    res.json({
      success: true,
      activities,
      pagination: {
        page,
        limit,
        hasMore: activities.length === limit
      }
    });
  } catch (error) {
    console.error('Dashboard activities error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to load activities'
    });
  }
});

// GET /dashboard/search - Global search
router.get('/search', async (req, res) => {
  try {
    const { q, type, page = 1, limit = 20 } = req.query;
    
    if (!q || q.trim().length < 2) {
      return res.json({
        success: false,
        error: 'Search query must be at least 2 characters'
      });
    }

    const searchResults = await performGlobalSearch(req.user, q, type, {
      page: parseInt(page),
      limit: parseInt(limit)
    });

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.json({
        success: true,
        ...searchResults
      });
    } else {
      res.render('dashboard/search', {
        title: 'Search Results',
        user: req.session.user,
        query: q,
        type,
        ...searchResults
      });
    }

  } catch (error) {
    console.error('Search error:', error);
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(500).json({
        success: false,
        error: 'Search failed'
      });
    } else {
      res.render('dashboard/search', {
        title: 'Search Results',
        user: req.session.user,
        query: req.query.q || '',
        type: req.query.type || '',
        results: [],
        total: 0,
        error: 'Search failed'
      });
    }
  }
});

// GET /dashboard/notifications - User notifications
router.get('/notifications', async (req, res) => {
  try {
    const notifications = await getUserNotifications(req.user);
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.json({
        success: true,
        notifications
      });
    } else {
      res.render('dashboard/notifications', {
        title: 'Notifications',
        user: req.session.user,
        notifications
      });
    }

  } catch (error) {
    console.error('Notifications error:', error);
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(500).json({
        success: false,
        error: 'Failed to load notifications'
      });
    } else {
      res.render('dashboard/notifications', {
        title: 'Notifications',
        user: req.session.user,
        notifications: [],
        error: 'Failed to load notifications'
      });
    }
  }
});

// POST /dashboard/notifications/:id/read - Mark notification as read
router.post('/notifications/:id/read', async (req, res) => {
  try {
    // Implement notification read functionality
    res.json({
      success: true,
      message: 'Notification marked as read'
    });
  } catch (error) {
    console.error('Mark notification read error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to mark notification as read'
    });
  }
});

// Helper function to get dashboard statistics
async function getDashboardStats(user) {
  const stats = {};

  try {
    // Get user's file count and total size
    const userFiles = await Attachment.find({ uploadedBy: user._id, isActive: true });
    stats.filesCount = userFiles.length;
    stats.totalFileSize = userFiles.reduce((total, file) => total + file.size, 0);

    // Get model counts user can access
    const availableModels = await getAvailableModels(user);
    stats.availableModels = availableModels.length;

    // Get recent activity count
    stats.recentActivities = await getRecentActivitiesCount(user);

    // If user has admin permissions, get system stats
    const hasAdminPermission = await user.hasPermission('system', 'read');
    if (hasAdminPermission) {
      const totalUsers = await User.countDocuments({ isActive: true });
      const totalRoles = await Role.countDocuments({ isActive: true });
      const totalModels = await DynamicModel.countDocuments({ isActive: true });
      const totalFiles = await Attachment.countDocuments({ isActive: true });

      stats.system = {
        totalUsers,
        totalRoles,
        totalModels,
        totalFiles
      };
    }

    return stats;

  } catch (error) {
    console.error('Error getting dashboard stats:', error);
    return stats;
  }
}

// Helper function to get recent activities
async function getRecentActivities(user, options = {}) {
  try {
    const { skip = 0, limit = 10 } = options;
    
    // This is a simplified implementation
    // In a real application, you'd have an Activity/Log model
    const activities = [];

    // Get recent file uploads
    const recentFiles = await Attachment.find({ 
      uploadedBy: user._id,
      isActive: true 
    })
    .sort({ createdAt: -1 })
    .limit(limit)
    .skip(skip);

    recentFiles.forEach(file => {
      activities.push({
        type: 'file_upload',
        description: `Uploaded file: ${file.originalName}`,
        timestamp: file.createdAt,
        icon: 'upload',
        color: 'blue'
      });
    });

    // Sort by timestamp
    activities.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    return activities.slice(0, limit);

  } catch (error) {
    console.error('Error getting recent activities:', error);
    return [];
  }
}

// Helper function to get recent activities count
async function getRecentActivitiesCount(user) {
  try {
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    
    const recentFilesCount = await Attachment.countDocuments({
      uploadedBy: user._id,
      createdAt: { $gte: oneDayAgo },
      isActive: true
    });

    return recentFilesCount;

  } catch (error) {
    console.error('Error getting recent activities count:', error);
    return 0;
  }
}

// Helper function to get available models for user
async function getAvailableModels(user) {
  try {
    const allModels = await DynamicModel.find({ isActive: true });
    const availableModels = [];

    for (const model of allModels) {
      // Check if user has any permission for this model
      const hasReadPermission = await user.hasPermission(model.name.toLowerCase(), 'read');
      const hasModelPermission = await checkModelPermission(user, model, 'read');
      
      if (hasReadPermission || hasModelPermission) {
        availableModels.push({
          id: model._id,
          name: model.name,
          displayName: model.displayName,
          description: model.description,
          icon: model.ui?.icon || 'database',
          color: model.ui?.color || 'gray',
          recordCount: await getModelRecordCount(model)
        });
      }
    }

    return availableModels;

  } catch (error) {
    console.error('Error getting available models:', error);
    return [];
  }
}

// Helper function to check model permission (simplified)
async function checkModelPermission(user, modelDef, action) {
  try {
    await user.populate('roles');
    
    for (const role of user.roles) {
      const rolePermission = modelDef.permissions.find(p => 
        p.role && p.role.toString() === role._id.toString()
      );
      
      if (rolePermission && rolePermission.actions.includes(action)) {
        return true;
      }
    }

    return false;
  } catch (error) {
    return false;
  }
}

// Helper function to get model record count
async function getModelRecordCount(modelDef) {
  try {
    const Model = modelDef.getModel();
    return await Model.countDocuments();
  } catch (error) {
    return 0;
  }
}

// Helper function to perform global search
async function performGlobalSearch(user, query, type, options = {}) {
  try {
    const { page = 1, limit = 20 } = options;
    const skip = (page - 1) * limit;
    const results = [];
    let total = 0;

    const searchRegex = new RegExp(query, 'i');

    // Search in files
    if (!type || type === 'files') {
      const fileQuery = {
        uploadedBy: user._id,
        isActive: true,
        $or: [
          { originalName: searchRegex },
          { description: searchRegex },
          { tags: { $in: [searchRegex] } }
        ]
      };

      const files = await Attachment.find(fileQuery)
        .sort({ createdAt: -1 })
        .limit(limit)
        .skip(skip);

      files.forEach(file => {
        results.push({
          type: 'file',
          id: file._id,
          title: file.originalName,
          description: file.description || `${file.formattedSize} • ${file.mimetype}`,
          url: `/attachments/${file._id}`,
          timestamp: file.createdAt,
          icon: 'file'
        });
      });

      if (!type) {
        total += await Attachment.countDocuments(fileQuery);
      }
    }

    // Search in available models
    if (!type || type === 'models') {
      const availableModels = await getAvailableModels(user);
      
      const modelResults = availableModels.filter(model =>
        model.name.toLowerCase().includes(query.toLowerCase()) ||
        model.displayName.toLowerCase().includes(query.toLowerCase()) ||
        (model.description && model.description.toLowerCase().includes(query.toLowerCase()))
      );

      modelResults.forEach(model => {
        results.push({
          type: 'model',
          id: model.id,
          title: model.displayName,
          description: model.description || `${model.recordCount} records`,
          url: `/models/${model.name}`,
          icon: model.icon
        });
      });

      if (!type) {
        total += modelResults.length;
      }
    }

    // Search in users (if user has permission)
    if ((!type || type === 'users') && await user.hasPermission('users', 'read')) {
      const userQuery = {
        isActive: true,
        $or: [
          { username: searchRegex },
          { firstName: searchRegex },
          { lastName: searchRegex },
          { email: searchRegex }
        ]
      };

      const users = await User.find(userQuery)
        .select('username firstName lastName email')
        .sort({ createdAt: -1 })
        .limit(limit)
        .skip(skip);

      users.forEach(userResult => {
        results.push({
          type: 'user',
          id: userResult._id,
          title: userResult.fullName,
          description: `@${userResult.username} • ${userResult.email}`,
          url: `/users/${userResult._id}`,
          icon: 'user'
        });
      });

      if (!type) {
        total += await User.countDocuments(userQuery);
      }
    }

    // Sort results by relevance and recency
    results.sort((a, b) => {
      // Prioritize exact matches
      const aExact = a.title.toLowerCase() === query.toLowerCase();
      const bExact = b.title.toLowerCase() === query.toLowerCase();
      
      if (aExact && !bExact) return -1;
      if (!aExact && bExact) return 1;
      
      // Then by timestamp
      return new Date(b.timestamp || 0) - new Date(a.timestamp || 0);
    });

    return {
      results: results.slice(0, limit),
      total: type ? results.length : total,
      query,
      type,
      pagination: {
        page,
        limit,
        hasMore: results.length > limit
      }
    };

  } catch (error) {
    console.error('Error performing global search:', error);
    return {
      results: [],
      total: 0,
      query,
      type,
      error: 'Search failed'
    };
  }
}

// Helper function to get user notifications (placeholder)
async function getUserNotifications(user) {
  try {
    // This is a placeholder implementation
    // In a real application, you'd have a Notification model
    const notifications = [
      {
        id: '1',
        title: 'Welcome to the system',
        message: 'Your account has been created successfully.',
        type: 'info',
        read: false,
        timestamp: new Date(),
        icon: 'info-circle'
      }
    ];

    return notifications;

  } catch (error) {
    console.error('Error getting user notifications:', error);
    return [];
  }
}

module.exports = router;
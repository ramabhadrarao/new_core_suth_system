// middleware/auth.js - Authentication and authorization middleware
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Role = require('../models/Role');
const DynamicModel = require('../models/DynamicModel');

// Middleware to check if user is authenticated
const requireAuth = async (req, res, next) => {
  try {
    // Check session first
    if (req.session && req.session.user) {
      return next();
    }

    // Check JWT token
    const token = req.cookies.accessToken || req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      if (req.xhr || req.headers.accept?.includes('application/json')) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }
      return res.redirect('/auth/login');
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-jwt-secret');
      const user = await User.findById(decoded.userId).populate('roles');
      
      if (!user || !user.isActive) {
        throw new Error('User not found or inactive');
      }

      // Set session if not exists
      if (!req.session.user) {
        req.session.user = {
          id: user._id,
          username: user.username,
          email: user.email,
          fullName: user.fullName,
          roles: user.roles,
          attributes: user.attributes
        };
      }

      req.user = user;
      next();

    } catch (tokenError) {
      // Try to refresh token
      const refreshToken = req.cookies.refreshToken;
      if (refreshToken) {
        try {
          const refreshDecoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET || 'your-refresh-secret');
          const user = await User.findById(refreshDecoded.userId).populate('roles');
          
          if (user && user.isActive) {
            const tokenData = user.refreshTokens.find(t => t.token === refreshToken && t.isActive);
            if (tokenData && tokenData.expiresAt > new Date()) {
              // Generate new access token
              const newAccessToken = user.generateAccessToken();
              
              res.cookie('accessToken', newAccessToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 15 * 60 * 1000
              });

              req.user = user;
              req.session.user = {
                id: user._id,
                username: user.username,
                email: user.email,
                fullName: user.fullName,
                roles: user.roles,
                attributes: user.attributes
              };

              return next();
            }
          }
        } catch (refreshError) {
          console.error('Refresh token error:', refreshError);
        }
      }

      // Clear invalid cookies
      res.clearCookie('accessToken');
      res.clearCookie('refreshToken');

      if (req.xhr || req.headers.accept?.includes('application/json')) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }
      return res.redirect('/auth/login');
    }

  } catch (error) {
    console.error('Auth middleware error:', error);
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      return res.status(500).json({
        success: false,
        error: 'Authentication error'
      });
    }
    return res.redirect('/auth/login?error=Authentication error');
  }
};

// Middleware to check permissions
const requirePermission = (resource, action, options = {}) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        if (req.xhr || req.headers.accept?.includes('application/json')) {
          return res.status(401).json({
            success: false,
            error: 'Authentication required'
          });
        }
        return res.redirect('/auth/login');
      }

      // Super admin bypass
      await req.user.populate('roles');
      const isSuperAdmin = req.user.roles.some(role => role.name === 'Super Admin');
      if (isSuperAdmin) {
        return next();
      }

      // Check permission
      const context = {
        user: req.user,
        ...options.context
      };

      const hasPermission = await req.user.hasPermission(resource, action, context);
      
      if (!hasPermission) {
        if (req.xhr || req.headers.accept?.includes('application/json')) {
          return res.status(403).json({
            success: false,
            error: 'Insufficient permissions'
          });
        }
        return res.status(403).render('error', {
          title: 'Access Denied',
          message: 'You do not have permission to access this resource.',
          user: req.session.user
        });
      }

      next();

    } catch (error) {
      console.error('Permission middleware error:', error);
      
      if (req.xhr || req.headers.accept?.includes('application/json')) {
        return res.status(500).json({
          success: false,
          error: 'Permission check error'
        });
      }
      return res.status(500).render('error', {
        title: 'Server Error',
        message: 'An error occurred checking permissions.',
        user: req.session.user
      });
    }
  };
};

// Middleware to check role
const requireRole = (roleName) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        if (req.xhr || req.headers.accept?.includes('application/json')) {
          return res.status(401).json({
            success: false,
            error: 'Authentication required'
          });
        }
        return res.redirect('/auth/login');
      }

      await req.user.populate('roles');
      const hasRole = req.user.roles.some(role => role.name === roleName);
      
      if (!hasRole) {
        if (req.xhr || req.headers.accept?.includes('application/json')) {
          return res.status(403).json({
            success: false,
            error: `Role '${roleName}' required`
          });
        }
        return res.status(403).render('error', {
          title: 'Access Denied',
          message: `You need the '${roleName}' role to access this resource.`,
          user: req.session.user
        });
      }

      next();

    } catch (error) {
      console.error('Role middleware error:', error);
      
      if (req.xhr || req.headers.accept?.includes('application/json')) {
        return res.status(500).json({
          success: false,
          error: 'Role check error'
        });
      }
      return res.status(500).render('error', {
        title: 'Server Error',
        message: 'An error occurred checking role.',
        user: req.session.user
      });
    }
  };
};

// Middleware for dynamic model permissions
const requireModelPermission = (action) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        if (req.xhr || req.headers.accept?.includes('application/json')) {
          return res.status(401).json({
            success: false,
            error: 'Authentication required'
          });
        }
        return res.redirect('/auth/login');
      }

      const modelName = req.params.modelName || req.body.modelName;
      
      if (!modelName) {
        if (req.xhr || req.headers.accept?.includes('application/json')) {
          return res.status(400).json({
            success: false,
            error: 'Model name required'
          });
        }
        return res.status(400).render('error', {
          title: 'Bad Request',
          message: 'Model name is required.',
          user: req.session.user
        });
      }

      // Get model definition
      const modelDef = await DynamicModel.findOne({ name: modelName, isActive: true });
      
      if (!modelDef) {
        if (req.xhr || req.headers.accept?.includes('application/json')) {
          return res.status(404).json({
            success: false,
            error: 'Model not found'
          });
        }
        return res.status(404).render('error', {
          title: 'Not Found',
          message: 'Model not found.',
          user: req.session.user
        });
      }

      // Super admin bypass
      await req.user.populate('roles');
      const isSuperAdmin = req.user.roles.some(role => role.name === 'Super Admin');
      if (isSuperAdmin) {
        req.modelDef = modelDef;
        return next();
      }

      // Check model-level permissions
      const hasModelPermission = await checkModelPermission(req.user, modelDef, action);
      
      if (!hasModelPermission) {
        if (req.xhr || req.headers.accept?.includes('application/json')) {
          return res.status(403).json({
            success: false,
            error: 'Insufficient model permissions'
          });
        }
        return res.status(403).render('error', {
          title: 'Access Denied',
          message: `You do not have permission to ${action} ${modelDef.displayName}.`,
          user: req.session.user
        });
      }

      req.modelDef = modelDef;
      next();

    } catch (error) {
      console.error('Model permission middleware error:', error);
      
      if (req.xhr || req.headers.accept?.includes('application/json')) {
        return res.status(500).json({
          success: false,
          error: 'Model permission check error'
        });
      }
      return res.status(500).render('error', {
        title: 'Server Error',
        message: 'An error occurred checking model permissions.',
        user: req.session.user
      });
    }
  };
};

// Helper function to check model permissions
const checkModelPermission = async (user, modelDef, action) => {
  // Check direct model permissions for user roles
  for (const role of user.roles) {
    const rolePermission = modelDef.permissions.find(p => 
      p.role && p.role.toString() === role._id.toString()
    );
    
    if (rolePermission && rolePermission.actions.includes(action)) {
      // Evaluate conditions if any
      const conditionsPassed = evaluateConditions(rolePermission.conditions, user);
      if (conditionsPassed) {
        return true;
      }
    }
  }

  // Check general permissions for the model resource
  const hasGeneralPermission = await user.hasPermission(modelDef.name.toLowerCase(), action);
  if (hasGeneralPermission) {
    return true;
  }

  return false;
};

// Helper function to evaluate ABAC conditions
const evaluateConditions = (conditions, user) => {
  if (!conditions || Object.keys(conditions).length === 0) {
    return true;
  }

  for (const [key, value] of Object.entries(conditions)) {
    const userValue = user.attributes[key];
    
    if (Array.isArray(value)) {
      if (!value.includes(userValue)) return false;
    } else if (typeof value === 'object' && value.operator) {
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

// Middleware to apply resource filters
const applyResourceFilters = (modelName) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return next();
      }

      // Super admin bypass
      await req.user.populate('roles');
      const isSuperAdmin = req.user.roles.some(role => role.name === 'Super Admin');
      if (isSuperAdmin) {
        return next();
      }

      // Get user's resource filters for this model
      const filters = req.user.getResourceFilters(modelName);
      
      // Apply filters to query
      if (filters && Object.keys(filters).length > 0) {
        req.resourceFilters = filters;
        
        // If there's a query object, merge filters
        if (req.query.filters) {
          try {
            const existingFilters = JSON.parse(req.query.filters);
            req.query.filters = JSON.stringify({ ...existingFilters, ...filters });
          } catch (e) {
            req.query.filters = JSON.stringify(filters);
          }
        } else {
          req.query.filters = JSON.stringify(filters);
        }
      }

      next();

    } catch (error) {
      console.error('Resource filter middleware error:', error);
      next();
    }
  };
};

// Optional authentication - sets user if authenticated but doesn't require it
const optionalAuth = async (req, res, next) => {
  try {
    const token = req.cookies.accessToken || req.headers.authorization?.replace('Bearer ', '');
    
    if (token) {
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-jwt-secret');
        const user = await User.findById(decoded.userId).populate('roles');
        
        if (user && user.isActive) {
          req.user = user;
          
          if (!req.session.user) {
            req.session.user = {
              id: user._id,
              username: user.username,
              email: user.email,
              fullName: user.fullName,
              roles: user.roles,
              attributes: user.attributes
            };
          }
        }
      } catch (tokenError) {
        // Token invalid, but that's okay for optional auth
        console.log('Optional auth token invalid:', tokenError.message);
      }
    }

    next();

  } catch (error) {
    console.error('Optional auth middleware error:', error);
    next();
  }
};

module.exports = {
  requireAuth,
  requirePermission,
  requireRole,
  requireModelPermission,
  applyResourceFilters,
  optionalAuth,
  checkModelPermission,
  evaluateConditions
};
// models/Role.js - Dynamic role model with permissions
const mongoose = require('mongoose');

const roleSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Role name is required'],
    unique: true,
    trim: true,
    minlength: [2, 'Role name must be at least 2 characters long'],
    maxlength: [50, 'Role name cannot exceed 50 characters']
  },
  description: {
    type: String,
    trim: true,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  permissions: [{
    resource: { 
      type: String, 
      required: true,
      trim: true
    },
    actions: [{ 
      type: String, 
      enum: ['create', 'read', 'update', 'delete', 'execute'],
      required: true
    }],
    conditions: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    },
    fields: [{
      name: String,
      access: { 
        type: String, 
        enum: ['read', 'write', 'none'], 
        default: 'read' 
      }
    }]
  }],
  // Role hierarchy - parent roles inherit permissions
  parentRoles: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Role'
  }],
  // Role attributes for ABAC
  attributes: {
    level: { 
      type: Number, 
      default: 1,
      min: 1,
      max: 10
    },
    scope: { 
      type: String, 
      enum: ['global', 'department', 'team', 'personal'], 
      default: 'personal' 
    },
    customAttributes: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    }
  },
  isActive: {
    type: Boolean,
    default: true
  },
  isSystemRole: {
    type: Boolean,
    default: false
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for users with this role
roleSchema.virtual('users', {
  ref: 'User',
  localField: '_id',
  foreignField: 'roles'
});

// Virtual for effective permissions (including inherited)
roleSchema.virtual('effectivePermissions').get(function() {
  let permissions = [...this.permissions];
  
  // Add inherited permissions from parent roles
  if (this.parentRoles && this.parentRoles.length > 0) {
    this.parentRoles.forEach(parentRole => {
      if (parentRole.permissions) {
        permissions = permissions.concat(parentRole.permissions);
      }
    });
  }
  
  // Remove duplicates and merge permissions for same resource
  const mergedPermissions = {};
  permissions.forEach(perm => {
    if (!mergedPermissions[perm.resource]) {
      mergedPermissions[perm.resource] = {
        resource: perm.resource,
        actions: [...perm.actions],
        conditions: { ...perm.conditions },
        fields: [...(perm.fields || [])]
      };
    } else {
      // Merge actions
      perm.actions.forEach(action => {
        if (!mergedPermissions[perm.resource].actions.includes(action)) {
          mergedPermissions[perm.resource].actions.push(action);
        }
      });
      
      // Merge conditions (OR logic)
      Object.assign(mergedPermissions[perm.resource].conditions, perm.conditions);
      
      // Merge fields
      if (perm.fields) {
        perm.fields.forEach(field => {
          const existingField = mergedPermissions[perm.resource].fields.find(f => f.name === field.name);
          if (!existingField) {
            mergedPermissions[perm.resource].fields.push(field);
          } else if (field.access === 'write' && existingField.access === 'read') {
            existingField.access = 'write';
          }
        });
      }
    }
  });
  
  return Object.values(mergedPermissions);
});

// Index for performance
roleSchema.index({ name: 1 });
roleSchema.index({ isActive: 1 });
roleSchema.index({ 'attributes.level': 1 });
roleSchema.index({ 'attributes.scope': 1 });

// Pre-save middleware
roleSchema.pre('save', function(next) {
  if (this.isNew) {
    this.createdBy = this.createdBy || null;
  }
  this.updatedBy = this.updatedBy || null;
  next();
});

// Method to check if role has permission
roleSchema.methods.hasPermission = function(resource, action) {
  const permission = this.effectivePermissions.find(p => p.resource === resource);
  return permission && permission.actions.includes(action);
};

// Method to add permission
roleSchema.methods.addPermission = function(resource, actions, conditions = {}, fields = []) {
  const existingPermIndex = this.permissions.findIndex(p => p.resource === resource);
  
  if (existingPermIndex >= 0) {
    // Update existing permission
    const existingPerm = this.permissions[existingPermIndex];
    actions.forEach(action => {
      if (!existingPerm.actions.includes(action)) {
        existingPerm.actions.push(action);
      }
    });
    Object.assign(existingPerm.conditions, conditions);
    if (fields.length > 0) {
      existingPerm.fields = fields;
    }
  } else {
    // Add new permission
    this.permissions.push({
      resource,
      actions: Array.isArray(actions) ? actions : [actions],
      conditions,
      fields
    });
  }
  
  return this.save();
};

// Method to remove permission
roleSchema.methods.removePermission = function(resource, action = null) {
  if (action) {
    // Remove specific action
    const permission = this.permissions.find(p => p.resource === resource);
    if (permission) {
      permission.actions = permission.actions.filter(a => a !== action);
      if (permission.actions.length === 0) {
        this.permissions = this.permissions.filter(p => p.resource !== resource);
      }
    }
  } else {
    // Remove entire resource permission
    this.permissions = this.permissions.filter(p => p.resource !== resource);
  }
  
  return this.save();
};

// Method to get users with this role
roleSchema.methods.getUsers = function() {
  return mongoose.model('User').find({ roles: this._id });
};

// Static method to get role hierarchy
roleSchema.statics.getRoleHierarchy = async function(roleId) {
  const role = await this.findById(roleId).populate('parentRoles');
  if (!role) return null;
  
  const hierarchy = [role];
  
  // Recursively get parent roles
  for (const parentRole of role.parentRoles) {
    const parentHierarchy = await this.getRoleHierarchy(parentRole._id);
    if (parentHierarchy) {
      hierarchy.push(...parentHierarchy);
    }
  }
  
  return hierarchy;
};

// Static method to create default roles
roleSchema.statics.createDefaultRoles = async function() {
  const defaultRoles = [
    {
      name: 'Super Admin',
      description: 'Full system access',
      permissions: [
        {
          resource: '*',
          actions: ['create', 'read', 'update', 'delete', 'execute']
        }
      ],
      attributes: {
        level: 10,
        scope: 'global'
      },
      isSystemRole: true
    },
    {
      name: 'Admin',
      description: 'Administrative access',
      permissions: [
        {
          resource: 'users',
          actions: ['create', 'read', 'update', 'delete']
        },
        {
          resource: 'roles',
          actions: ['read', 'update']
        }
      ],
      attributes: {
        level: 8,
        scope: 'department'
      },
      isSystemRole: true
    },
    {
      name: 'Manager',
      description: 'Management access',
      permissions: [
        {
          resource: 'users',
          actions: ['read', 'update'],
          conditions: { department: '${user.attributes.department}' }
        }
      ],
      attributes: {
        level: 6,
        scope: 'team'
      },
      isSystemRole: true
    },
    {
      name: 'User',
      description: 'Basic user access',
      permissions: [
        {
          resource: 'profile',
          actions: ['read', 'update']
        },
        {
          resource: 'attachments',
          actions: ['read', 'create']
        }
      ],
      attributes: {
        level: 1,
        scope: 'personal'
      },
      isSystemRole: true
    }
  ];
  
  for (const roleData of defaultRoles) {
    const existingRole = await this.findOne({ name: roleData.name });
    if (!existingRole) {
      await this.create(roleData);
    }
  }
};

module.exports = mongoose.model('Role', roleSchema);
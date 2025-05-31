// models/Attachment.js - File attachment model with permissions
const mongoose = require('mongoose');
const path = require('path');
const fs = require('fs').promises;

const attachmentSchema = new mongoose.Schema({
  filename: {
    type: String,
    required: [true, 'Filename is required'],
    trim: true
  },
  originalName: {
    type: String,
    required: [true, 'Original filename is required'],
    trim: true
  },
  mimetype: {
    type: String,
    required: [true, 'MIME type is required']
  },
  size: {
    type: Number,
    required: [true, 'File size is required'],
    min: [0, 'File size cannot be negative']
  },
  path: {
    type: String,
    required: [true, 'File path is required']
  },
  // File metadata
  metadata: {
    width: Number,
    height: Number,
    duration: Number, // For video/audio files
    pages: Number,    // For PDF files
    encoding: String,
    format: String,
    customMetadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    }
  },
  // File categorization
  category: {
    type: String,
    enum: ['document', 'image', 'video', 'audio', 'archive', 'other'],
    default: 'other'
  },
  tags: [String],
  description: {
    type: String,
    trim: true,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  // Ownership and permissions
  uploadedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  // Access control
  visibility: {
    type: String,
    enum: ['private', 'internal', 'public'],
    default: 'private'
  },
  permissions: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    role: { type: mongoose.Schema.Types.ObjectId, ref: 'Role' },
    access: { 
      type: String, 
      enum: ['read', 'write', 'delete'], 
      default: 'read' 
    }
  }],
  // File versioning
  version: {
    type: Number,
    default: 1
  },
  previousVersions: [{
    filename: String,
    path: String,
    version: Number,
    uploadedAt: Date,
    uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
  }],
  // File relationships
  relatedTo: {
    model: String,    // Model name (e.g., 'Product', 'User')
    documentId: mongoose.Schema.Types.ObjectId,
    field: String     // Field name in the related document
  },
  // File processing status
  processingStatus: {
    type: String,
    enum: ['pending', 'processing', 'completed', 'failed'],
    default: 'completed'
  },
  processingError: String,
  // Thumbnails and previews
  thumbnails: [{
    size: String,     // e.g., '150x150', 'small', 'medium', 'large'
    path: String,
    mimetype: String
  }],
  // File expiration
  expiresAt: Date,
  // Download tracking
  downloadCount: {
    type: Number,
    default: 0
  },
  lastDownloadedAt: Date,
  lastDownloadedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  // Virus scan results
  virusScanStatus: {
    type: String,
    enum: ['pending', 'clean', 'infected', 'error'],
    default: 'pending'
  },
  virusScanDate: Date,
  // File hash for integrity checking
  hash: {
    md5: String,
    sha256: String
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for file URL
attachmentSchema.virtual('url').get(function() {
  return `/uploads/${this.filename}`;
});

// Virtual for file extension
attachmentSchema.virtual('extension').get(function() {
  return path.extname(this.originalName).toLowerCase();
});

// Virtual for formatted file size
attachmentSchema.virtual('formattedSize').get(function() {
  const bytes = this.size;
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
});

// Virtual for file type category
attachmentSchema.virtual('fileType').get(function() {
  const ext = this.extension;
  
  if (['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg'].includes(ext)) {
    return 'image';
  } else if (['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv'].includes(ext)) {
    return 'video';
  } else if (['.mp3', '.wav', '.ogg', '.m4a', '.aac'].includes(ext)) {
    return 'audio';
  } else if (['.pdf', '.doc', '.docx', '.txt', '.rtf'].includes(ext)) {
    return 'document';
  } else if (['.zip', '.rar', '.7z', '.tar', '.gz'].includes(ext)) {
    return 'archive';
  } else {
    return 'other';
  }
});

// Indexes for performance
attachmentSchema.index({ uploadedBy: 1 });
attachmentSchema.index({ 'relatedTo.model': 1, 'relatedTo.documentId': 1 });
attachmentSchema.index({ category: 1 });
attachmentSchema.index({ mimetype: 1 });
attachmentSchema.index({ createdAt: -1 });
attachmentSchema.index({ tags: 1 });
attachmentSchema.index({ expiresAt: 1 });

// Pre-save middleware
attachmentSchema.pre('save', function(next) {
  // Set category based on file type
  if (!this.category || this.category === 'other') {
    this.category = this.fileType;
  }
  
  // Set expiration date if not set (default 1 year)
  if (!this.expiresAt && this.visibility === 'private') {
    this.expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
  }
  
  next();
});

// Method to check if user can access file
attachmentSchema.methods.canAccess = async function(user, action = 'read') {
  // File owner always has access
  if (this.uploadedBy.toString() === user._id.toString()) {
    return true;
  }
  
  // Check visibility
  if (this.visibility === 'public') {
    return action === 'read';
  }
  
  // Check direct user permissions
  const userPermission = this.permissions.find(p => 
    p.user && p.user.toString() === user._id.toString()
  );
  if (userPermission) {
    return this.checkPermissionLevel(userPermission.access, action);
  }
  
  // Check role-based permissions
  await user.populate('roles');
  for (const role of user.roles) {
    const rolePermission = this.permissions.find(p => 
      p.role && p.role.toString() === role._id.toString()
    );
    if (rolePermission) {
      return this.checkPermissionLevel(rolePermission.access, action);
    }
  }
  
  // Check if user has general file permissions
  const hasFilePermission = await user.hasPermission('attachments', action);
  if (hasFilePermission && this.visibility === 'internal') {
    return true;
  }
  
  return false;
};

// Helper method to check permission levels
attachmentSchema.methods.checkPermissionLevel = function(permissionLevel, action) {
  const levels = {
    'read': ['read'],
    'write': ['read', 'write'],
    'delete': ['read', 'write', 'delete']
  };
  
  return levels[permissionLevel] && levels[permissionLevel].includes(action);
};

// Method to add permission
attachmentSchema.methods.addPermission = function(userOrRole, access, isRole = false) {
  const field = isRole ? 'role' : 'user';
  const existingPermission = this.permissions.find(p => 
    p[field] && p[field].toString() === userOrRole.toString()
  );
  
  if (existingPermission) {
    existingPermission.access = access;
  } else {
    const permission = { access };
    permission[field] = userOrRole;
    this.permissions.push(permission);
  }
  
  return this.save();
};

// Method to remove permission
attachmentSchema.methods.removePermission = function(userOrRole, isRole = false) {
  const field = isRole ? 'role' : 'user';
  this.permissions = this.permissions.filter(p => 
    !p[field] || p[field].toString() !== userOrRole.toString()
  );
  
  return this.save();
};

// Method to create new version
attachmentSchema.methods.createVersion = function(newFileData) {
  // Store current version in history
  this.previousVersions.push({
    filename: this.filename,
    path: this.path,
    version: this.version,
    uploadedAt: this.updatedAt,
    uploadedBy: this.uploadedBy
  });
  
  // Update with new file data
  this.filename = newFileData.filename;
  this.path = newFileData.path;
  this.size = newFileData.size;
  this.mimetype = newFileData.mimetype;
  this.version += 1;
  this.processingStatus = 'pending';
  
  return this.save();
};

// Method to track download
attachmentSchema.methods.trackDownload = function(userId) {
  this.downloadCount += 1;
  this.lastDownloadedAt = new Date();
  this.lastDownloadedBy = userId;
  
  return this.save();
};

// Method to delete file and cleanup
attachmentSchema.methods.deleteFile = async function() {
  try {
    // Delete main file
    await fs.unlink(this.path);
    
    // Delete thumbnails
    for (const thumbnail of this.thumbnails) {
      try {
        await fs.unlink(thumbnail.path);
      } catch (e) {
        console.error('Error deleting thumbnail:', e);
      }
    }
    
    // Delete previous versions
    for (const version of this.previousVersions) {
      try {
        await fs.unlink(version.path);
      } catch (e) {
        console.error('Error deleting version:', e);
      }
    }
    
    // Remove from database
    await this.deleteOne();
    
    return true;
  } catch (error) {
    console.error('Error deleting file:', error);
    return false;
  }
};

// Static method to cleanup expired files
attachmentSchema.statics.cleanupExpiredFiles = async function() {
  const expiredFiles = await this.find({
    expiresAt: { $lt: new Date() },
    isActive: true
  });
  
  for (const file of expiredFiles) {
    await file.deleteFile();
  }
  
  return expiredFiles.length;
};

// Static method to get user's files
attachmentSchema.statics.getUserFiles = function(userId, options = {}) {
  const query = { uploadedBy: userId, isActive: true };
  
  if (options.category) {
    query.category = options.category;
  }
  
  if (options.tags && options.tags.length > 0) {
    query.tags = { $in: options.tags };
  }
  
  return this.find(query)
    .sort(options.sort || { createdAt: -1 })
    .limit(options.limit || 50)
    .skip(options.skip || 0);
};

module.exports = mongoose.model('Attachment', attachmentSchema);

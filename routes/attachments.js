// routes/attachments.js - File management routes
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');
const { requireAuth, requirePermission } = require('../middleware/auth');
const Attachment = require('../models/Attachment');

const router = express.Router();

// All routes require authentication
router.use(requireAuth);

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadPath = path.join(__dirname, '../uploads');
    try {
      await fs.mkdir(uploadPath, { recursive: true });
      cb(null, uploadPath);
    } catch (error) {
      cb(error);
    }
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  }
});

const fileFilter = (req, file, cb) => {
  // Define allowed file types
  const allowedMimes = [
    'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'text/plain', 'text/csv',
    'application/zip', 'application/x-rar-compressed'
  ];

  if (allowedMimes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('File type not allowed'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024 // 10MB default
  }
});

// GET /attachments - List files
router.get('/', requirePermission('attachments', 'read'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    const search = req.query.search || '';
    const category = req.query.category || '';
    const visibility = req.query.visibility || '';

    // Build query based on user permissions
    let query = { isActive: true };
    
    // Super admin can see all files
    await req.user.populate('roles');
    const isSuperAdmin = req.user.roles.some(role => role.name === 'Super Admin');
    
    if (!isSuperAdmin) {
      // Regular users see their own files and files they have access to
      query.$or = [
        { uploadedBy: req.user._id },
        { visibility: 'public' },
        { 
          visibility: 'internal',
          $or: [
            { 'permissions.user': req.user._id },
            { 'permissions.role': { $in: req.user.roles.map(r => r._id) } }
          ]
        }
      ];
    }

    if (search) {
      query.$and = query.$and || [];
      query.$and.push({
        $or: [
          { originalName: { $regex: search, $options: 'i' } },
          { description: { $regex: search, $options: 'i' } },
          { tags: { $in: [new RegExp(search, 'i')] } }
        ]
      });
    }

    if (category) {
      query.category = category;
    }

    if (visibility) {
      query.visibility = visibility;
    }

    // Get files with pagination
    const files = await Attachment.find(query)
      .populate('uploadedBy', 'firstName lastName username')
      .sort({ createdAt: -1 })
      .limit(limit)
      .skip(skip);

    const total = await Attachment.countDocuments(query);
    const totalPages = Math.ceil(total / limit);

    // Get categories for filter
    const categories = await Attachment.distinct('category', { isActive: true });

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.json({
        success: true,
        files,
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
      res.render('attachments/index', {
        title: 'File Management',
        currentPage: 'attachments',
        files,
        categories,
        pagination: {
          page,
          limit,
          total,
          totalPages,
          hasNext: page < totalPages,
          hasPrev: page > 1
        },
        filters: { search, category, visibility },
        user: req.session.user
      });
    }

  } catch (error) {
    console.error('Error listing files:', error);
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(500).json({
        success: false,
        error: 'Failed to load files'
      });
    } else {
      res.render('attachments/index', {
        title: 'File Management',
        currentPage: 'attachments',
        files: [],
        categories: [],
        pagination: {},
        filters: {},
        error: 'Failed to load files',
        user: req.session.user
      });
    }
  }
});

// GET /attachments/upload - Upload form
router.get('/upload', requirePermission('attachments', 'create'), (req, res) => {
  res.render('attachments/upload', {
    title: 'Upload Files',
    currentPage: 'attachments',
    user: req.session.user
  });
});

// POST /attachments/upload - Upload files
router.post('/upload', requirePermission('attachments', 'create'), upload.array('files', 10), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'No files uploaded'
      });
    }

    const { description, tags, visibility, category } = req.body;
    const uploadedFiles = [];

    for (const file of req.files) {
      try {
        // Calculate file hash
        const fileBuffer = await fs.readFile(file.path);
        const hash = {
          md5: crypto.createHash('md5').update(fileBuffer).digest('hex'),
          sha256: crypto.createHash('sha256').update(fileBuffer).digest('hex')
        };

        // Create attachment record
        const attachment = new Attachment({
          filename: file.filename,
          originalName: file.originalname,
          mimetype: file.mimetype,
          size: file.size,
          path: file.path,
          description: description || '',
          tags: tags ? tags.split(',').map(tag => tag.trim()) : [],
          visibility: visibility || 'private',
          category: category || 'other',
          uploadedBy: req.user._id,
          hash,
          virusScanStatus: 'clean' // In production, implement actual virus scanning
        });

        await attachment.save();
        uploadedFiles.push(attachment);

      } catch (fileError) {
        console.error('Error processing file:', fileError);
        // Clean up file if error occurs
        try {
          await fs.unlink(file.path);
        } catch (unlinkError) {
          console.error('Error deleting file:', unlinkError);
        }
      }
    }

    if (uploadedFiles.length === 0) {
      return res.status(500).json({
        success: false,
        error: 'Failed to process any files'
      });
    }

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(201).json({
        success: true,
        message: `${uploadedFiles.length} file(s) uploaded successfully`,
        files: uploadedFiles
      });
    } else {
      res.redirect('/attachments?message=' + encodeURIComponent(`${uploadedFiles.length} file(s) uploaded successfully`));
    }

  } catch (error) {
    console.error('Error uploading files:', error);
    
    // Clean up uploaded files on error
    if (req.files) {
      for (const file of req.files) {
        try {
          await fs.unlink(file.path);
        } catch (unlinkError) {
          console.error('Error deleting file:', unlinkError);
        }
      }
    }

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(500).json({
        success: false,
        error: 'Failed to upload files'
      });
    } else {
      res.redirect('/attachments?error=Failed to upload files');
    }
  }
});

// GET /attachments/:id - View file details
router.get('/:id', async (req, res) => {
  try {
    const file = await Attachment.findById(req.params.id)
      .populate('uploadedBy', 'firstName lastName username');

    if (!file) {
      if (req.xhr || req.headers.accept?.includes('application/json')) {
        return res.status(404).json({
          success: false,
          error: 'File not found'
        });
      } else {
        return res.redirect('/attachments?error=File not found');
      }
    }

    // Check access permissions
    const canAccess = await file.canAccess(req.user, 'read');
    if (!canAccess) {
      if (req.xhr || req.headers.accept?.includes('application/json')) {
        return res.status(403).json({
          success: false,
          error: 'Access denied'
        });
      } else {
        return res.redirect('/attachments?error=Access denied');
      }
    }

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.json({
        success: true,
        file
      });
    } else {
      res.render('attachments/view', {
        title: `File: ${file.originalName}`,
        currentPage: 'attachments',
        file,
        user: req.session.user
      });
    }

  } catch (error) {
    console.error('Error viewing file:', error);
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(500).json({
        success: false,
        error: 'Failed to load file'
      });
    } else {
      res.redirect('/attachments?error=Failed to load file');
    }
  }
});

// GET /attachments/:id/download - Download file
router.get('/:id/download', async (req, res) => {
  try {
    const file = await Attachment.findById(req.params.id);

    if (!file) {
      return res.status(404).json({
        success: false,
        error: 'File not found'
      });
    }

    // Check access permissions
    const canAccess = await file.canAccess(req.user, 'read');
    if (!canAccess) {
      return res.status(403).json({
        success: false,
        error: 'Access denied'
      });
    }

    // Check if file exists on disk
    try {
      await fs.access(file.path);
    } catch (error) {
      return res.status(404).json({
        success: false,
        error: 'File not found on disk'
      });
    }

    // Track download
    await file.trackDownload(req.user._id);

    // Set headers for download
    res.setHeader('Content-Disposition', `attachment; filename="${file.originalName}"`);
    res.setHeader('Content-Type', file.mimetype);
    res.setHeader('Content-Length', file.size);

    // Stream file
    const fileStream = require('fs').createReadStream(file.path);
    fileStream.pipe(res);

  } catch (error) {
    console.error('Error downloading file:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to download file'
    });
  }
});

// PUT /attachments/:id - Update file metadata
router.put('/:id', async (req, res) => {
  try {
    const file = await Attachment.findById(req.params.id);

    if (!file) {
      return res.status(404).json({
        success: false,
        error: 'File not found'
      });
    }

    // Check access permissions
    const canAccess = await file.canAccess(req.user, 'write');
    if (!canAccess) {
      return res.status(403).json({
        success: false,
        error: 'Access denied'
      });
    }

    const { description, tags, visibility, category } = req.body;

    // Update metadata
    if (description !== undefined) file.description = description;
    if (tags !== undefined) {
      file.tags = Array.isArray(tags) ? tags : tags.split(',').map(tag => tag.trim());
    }
    if (visibility !== undefined) file.visibility = visibility;
    if (category !== undefined) file.category = category;

    await file.save();

    res.json({
      success: true,
      message: 'File updated successfully'
    });

  } catch (error) {
    console.error('Error updating file:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update file'
    });
  }
});

// DELETE /attachments/:id - Delete file
router.delete('/:id', async (req, res) => {
  try {
    const file = await Attachment.findById(req.params.id);

    if (!file) {
      return res.status(404).json({
        success: false,
        error: 'File not found'
      });
    }

    // Check access permissions
    const canAccess = await file.canAccess(req.user, 'delete');
    if (!canAccess) {
      return res.status(403).json({
        success: false,
        error: 'Access denied'
      });
    }

    // Delete file and cleanup
    const success = await file.deleteFile();

    if (success) {
      res.json({
        success: true,
        message: 'File deleted successfully'
      });
    } else {
      res.status(500).json({
        success: false,
        error: 'Failed to delete file'
      });
    }

  } catch (error) {
    console.error('Error deleting file:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete file'
    });
  }
});

// POST /attachments/:id/permissions - Update file permissions
router.post('/:id/permissions', async (req, res) => {
  try {
    const file = await Attachment.findById(req.params.id);

    if (!file) {
      return res.status(404).json({
        success: false,
        error: 'File not found'
      });
    }

    // Check if user is owner or has admin permissions
    const isOwner = file.uploadedBy.toString() === req.user._id.toString();
    const hasAdminPermission = await req.user.hasPermission('attachments', 'update');

    if (!isOwner && !hasAdminPermission) {
      return res.status(403).json({
        success: false,
        error: 'Access denied'
      });
    }

    const { userId, roleId, access } = req.body;

    if (userId) {
      await file.addPermission(userId, access, false);
    } else if (roleId) {
      await file.addPermission(roleId, access, true);
    } else {
      return res.status(400).json({
        success: false,
        error: 'User ID or Role ID is required'
      });
    }

    res.json({
      success: true,
      message: 'Permissions updated successfully'
    });

  } catch (error) {
    console.error('Error updating file permissions:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update permissions'
    });
  }
});

// DELETE /attachments/:id/permissions - Remove file permissions
router.delete('/:id/permissions', async (req, res) => {
  try {
    const file = await Attachment.findById(req.params.id);

    if (!file) {
      return res.status(404).json({
        success: false,
        error: 'File not found'
      });
    }

    // Check if user is owner or has admin permissions
    const isOwner = file.uploadedBy.toString() === req.user._id.toString();
    const hasAdminPermission = await req.user.hasPermission('attachments', 'update');

    if (!isOwner && !hasAdminPermission) {
      return res.status(403).json({
        success: false,
        error: 'Access denied'
      });
    }

    const { userId, roleId } = req.body;

    if (userId) {
      await file.removePermission(userId, false);
    } else if (roleId) {
      await file.removePermission(roleId, true);
    } else {
      return res.status(400).json({
        success: false,
        error: 'User ID or Role ID is required'
      });
    }

    res.json({
      success: true,
      message: 'Permission removed successfully'
    });

  } catch (error) {
    console.error('Error removing file permission:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to remove permission'
    });
  }
});

// GET /attachments/stats - File statistics
router.get('/stats', requirePermission('attachments', 'read'), async (req, res) => {
  try {
    // Get file statistics
    const totalFiles = await Attachment.countDocuments({ isActive: true });
    const userFiles = await Attachment.countDocuments({ 
      uploadedBy: req.user._id, 
      isActive: true 
    });

    // Get size statistics
    const sizeStats = await Attachment.aggregate([
      { $match: { isActive: true } },
      { 
        $group: {
          _id: null,
          totalSize: { $sum: '$size' },
          avgSize: { $avg: '$size' }
        }
      }
    ]);

    // Get category distribution
    const categoryStats = await Attachment.aggregate([
      { $match: { isActive: true } },
      { 
        $group: {
          _id: '$category',
          count: { $sum: 1 },
          totalSize: { $sum: '$size' }
        }
      }
    ]);

    res.json({
      success: true,
      stats: {
        totalFiles,
        userFiles,
        totalSize: sizeStats[0]?.totalSize || 0,
        avgSize: sizeStats[0]?.avgSize || 0,
        categoryDistribution: categoryStats
      }
    });

  } catch (error) {
    console.error('Error getting file statistics:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get statistics'
    });
  }
});

module.exports = router;
// routes/models.js - Dynamic model management routes
const express = require('express');
const { body, validationResult } = require('express-validator');
const { requireAuth, requirePermission, requireModelPermission } = require('../middleware/auth');
const DynamicModel = require('../models/DynamicModel');
const mongoose = require('mongoose');

const router = express.Router();

// All routes require authentication
router.use(requireAuth);

// GET /models - List dynamic models
router.get('/', requirePermission('models', 'read'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    const search = req.query.search || '';

    // Build query
    const query = { isActive: true };
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { displayName: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    // Get models with pagination
    const models = await DynamicModel.find(query)
      .populate('createdBy', 'firstName lastName username')
      .sort({ createdAt: -1 })
      .limit(limit)
      .skip(skip);

    const total = await DynamicModel.countDocuments(query);
    const totalPages = Math.ceil(total / limit);

    // Get record counts for each model
    const modelsWithCounts = await Promise.all(
      models.map(async (model) => {
        try {
          const Model = model.getModel();
          const recordCount = await Model.countDocuments();
          return {
            ...model.toObject(),
            recordCount
          };
        } catch (error) {
          return {
            ...model.toObject(),
            recordCount: 0
          };
        }
      })
    );

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.json({
        success: true,
        models: modelsWithCounts,
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
      res.render('admin/models/index', {
        title: 'Dynamic Models',
        currentPage: 'models',
        models: modelsWithCounts,
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
    console.error('Error listing models:', error);
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(500).json({
        success: false,
        error: 'Failed to load models'
      });
    } else {
      res.render('admin/models/index', {
        title: 'Dynamic Models',
        currentPage: 'models',
        models: [],
        pagination: {},
        filters: {},
        error: 'Failed to load models',
        user: req.session.user
      });
    }
  }
});

// GET /models/new - Create model form
router.get('/new', requirePermission('models', 'create'), async (req, res) => {
  try {
    const fieldTypes = [
      'String', 'Number', 'Boolean', 'Date', 'ObjectId', 'Array', 'Mixed', 'Email', 'URL', 'Phone'
    ];

    const widgetTypes = [
      'text', 'textarea', 'select', 'checkbox', 'radio', 'date', 'file', 'password', 'email', 'number'
    ];

    res.render('admin/models/form', {
      title: 'Create Dynamic Model',
      currentPage: 'models',
      modelData: {},
      fieldTypes,
      widgetTypes,
      isEdit: false,
      user: req.session.user
    });

  } catch (error) {
    console.error('Error loading create model form:', error);
    res.redirect('/models?error=Failed to load create form');
  }
});

// POST /models - Create new model
router.post('/', requirePermission('models', 'create'), [
  body('name').isLength({ min: 1, max: 50 }).matches(/^[a-zA-Z][a-zA-Z0-9_]*$/),
  body('displayName').isLength({ min: 1, max: 100 }).trim(),
  body('collection').isLength({ min: 1, max: 50 }).matches(/^[a-z][a-z0-9_]*$/)
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const { name, displayName, description, collection, fields, icon, color } = req.body;

    // Check if model already exists
    const existingModel = await DynamicModel.findOne({
      $or: [{ name }, { collection }]
    });

    if (existingModel) {
      return res.status(400).json({
        success: false,
        error: 'Model with this name or collection already exists'
      });
    }

    // Validate fields
    if (!fields || !Array.isArray(fields) || fields.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'At least one field is required'
      });
    }

    // Create model
    const model = new DynamicModel({
      name,
      displayName,
      description,
      collection,
      fields: fields.map((field, index) => ({
        ...field,
        order: field.order || index
      })),
      ui: {
        icon: icon || 'database',
        color: color || 'blue'
      },
      createdBy: req.user._id
    });

    await model.save();

    // Create the actual mongoose model
    try {
      model.getModel();
    } catch (modelError) {
      console.error('Error creating mongoose model:', modelError);
      await model.deleteOne();
      return res.status(400).json({
        success: false,
        error: 'Invalid model definition: ' + modelError.message
      });
    }

    res.status(201).json({
      success: true,
      message: 'Model created successfully',
      modelId: model._id
    });

  } catch (error) {
    console.error('Error creating model:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to create model'
    });
  }
});

// GET /models/:id - View model details
router.get('/:id', requirePermission('models', 'read'), async (req, res) => {
  try {
    const modelData = await DynamicModel.findById(req.params.id)
      .populate('createdBy', 'firstName lastName username');

    if (!modelData) {
      if (req.xhr || req.headers.accept?.includes('application/json')) {
        return res.status(404).json({
          success: false,
          error: 'Model not found'
        });
      } else {
        return res.redirect('/models?error=Model not found');
      }
    }

    // Get record count
    let recordCount = 0;
    try {
      const Model = modelData.getModel();
      recordCount = await Model.countDocuments();
    } catch (error) {
      console.error('Error getting record count:', error);
    }

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.json({
        success: true,
        model: modelData,
        recordCount
      });
    } else {
      res.render('admin/models/view', {
        title: `Model: ${modelData.displayName}`,
        currentPage: 'models',
        modelData,
        recordCount,
        user: req.session.user
      });
    }

  } catch (error) {
    console.error('Error viewing model:', error);
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(500).json({
        success: false,
        error: 'Failed to load model'
      });
    } else {
      res.redirect('/models?error=Failed to load model');
    }
  }
});

// GET /models/:id/edit - Edit model form
router.get('/:id/edit', requirePermission('models', 'update'), async (req, res) => {
  try {
    const modelData = await DynamicModel.findById(req.params.id);

    if (!modelData) {
      return res.redirect('/models?error=Model not found');
    }

    const fieldTypes = [
      'String', 'Number', 'Boolean', 'Date', 'ObjectId', 'Array', 'Mixed', 'Email', 'URL', 'Phone'
    ];

    const widgetTypes = [
      'text', 'textarea', 'select', 'checkbox', 'radio', 'date', 'file', 'password', 'email', 'number'
    ];
    
    res.render('admin/models/form', {
      title: `Edit Model: ${modelData.displayName}`,
      currentPage: 'models',
      modelData,
      fieldTypes,
      widgetTypes,
      isEdit: true,
      user: req.session.user
    });

  } catch (error) {
    console.error('Error loading edit model form:', error);
    res.redirect('/models?error=Failed to load edit form');
  }
});

// PUT /models/:id - Update model
router.put('/:id', requirePermission('models', 'update'), [
  body('displayName').isLength({ min: 1, max: 100 }).trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: errors.array()[0].msg
      });
    }

    const modelData = await DynamicModel.findById(req.params.id);
    if (!modelData) {
      return res.status(404).json({
        success: false,
        error: 'Model not found'
      });
    }

    const { displayName, description, fields, icon, color } = req.body;

    // Update model data (name and collection cannot be changed)
    modelData.displayName = displayName;
    modelData.description = description;
    
    if (fields && Array.isArray(fields)) {
      modelData.fields = fields.map((field, index) => ({
        ...field,
        order: field.order || index
      }));
    }
    
    modelData.ui.icon = icon || modelData.ui.icon;
    modelData.ui.color = color || modelData.ui.color;
    modelData.updatedBy = req.user._id;

    await modelData.save();

    res.json({
      success: true,
      message: 'Model updated successfully'
    });

  } catch (error) {
    console.error('Error updating model:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update model'
    });
  }
});

// DELETE /models/:id - Delete model
router.delete('/:id', requirePermission('models', 'delete'), async (req, res) => {
  try {
    const modelData = await DynamicModel.findById(req.params.id);
    
    if (!modelData) {
      return res.status(404).json({
        success: false,
        error: 'Model not found'
      });
    }

    // Check if model has records
    try {
      const Model = modelData.getModel();
      const recordCount = await Model.countDocuments();
      
      if (recordCount > 0) {
        return res.status(400).json({
          success: false,
          error: `Cannot delete model. It contains ${recordCount} record(s)`
        });
      }
    } catch (error) {
      console.error('Error checking model records:', error);
    }

    // Soft delete by deactivating
    modelData.isActive = false;
    await modelData.save();

    res.json({
      success: true,
      message: 'Model deleted successfully'
    });

  } catch (error) {
    console.error('Error deleting model:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete model'
    });
  }
});

// GET /models/:modelName/data - Get model records
router.get('/:modelName/data', requireModelPermission('read'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;
    const search = req.query.search || '';
    const sort = req.query.sort || 'createdAt';
    const order = req.query.order === 'asc' ? 1 : -1;

    const Model = req.modelDef.getModel();

    // Build query
    let query = {};
    
    if (search) {
      // Search across text fields
      const textFields = req.modelDef.fields
        .filter(field => ['String', 'Email'].includes(field.type))
        .map(field => field.name);
      
      if (textFields.length > 0) {
        query.$or = textFields.map(field => ({
          [field]: { $regex: search, $options: 'i' }
        }));
      }
    }

    // Apply resource filters
    if (req.resourceFilters) {
      query = { ...query, ...req.resourceFilters };
    }

    // Get records with pagination
    const records = await Model.find(query)
      .sort({ [sort]: order })
      .limit(limit)
      .skip(skip)
      .populate(getPopulateFields(req.modelDef.fields));

    const total = await Model.countDocuments(query);
    const totalPages = Math.ceil(total / limit);

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.json({
        success: true,
        records,
        pagination: {
          page,
          limit,
          total,
          totalPages,
          hasNext: page < totalPages,
          hasPrev: page > 1
        },
        modelDef: req.modelDef
      });
    } else {
      res.render('models/data/index', {
        title: `${req.modelDef.displayName} Records`,
        currentPage: 'models',
        modelDef: req.modelDef,
        records,
        pagination: {
          page,
          limit,
          total,
          totalPages,
          hasNext: page < totalPages,
          hasPrev: page > 1
        },
        filters: { search, sort, order },
        user: req.session.user
      });
    }

  } catch (error) {
    console.error('Error getting model records:', error);
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(500).json({
        success: false,
        error: 'Failed to load records'
      });
    } else {
      res.render('models/data/index', {
        title: 'Records',
        currentPage: 'models',
        modelDef: req.modelDef,
        records: [],
        pagination: {},
        filters: {},
        error: 'Failed to load records',
        user: req.session.user
      });
    }
  }
});

// GET /models/:modelName/data/new - Create record form
router.get('/:modelName/data/new', requireModelPermission('create'), async (req, res) => {
  try {
    res.render('models/data/form', {
      title: `Create ${req.modelDef.displayName}`,
      currentPage: 'models',
      modelDef: req.modelDef,
      recordData: {},
      isEdit: false,
      user: req.session.user
    });

  } catch (error) {
    console.error('Error loading create record form:', error);
    res.redirect(`/models/${req.params.modelName}/data?error=Failed to load create form`);
  }
});

// POST /models/:modelName/data - Create new record
router.post('/:modelName/data', requireModelPermission('create'), async (req, res) => {
  try {
    const Model = req.modelDef.getModel();
    const recordData = processFormData(req.body, req.modelDef.fields);

    // Validate required fields
    const validationErrors = validateRecord(recordData, req.modelDef.fields);
    if (validationErrors.length > 0) {
      return res.status(400).json({
        success: false,
        error: validationErrors[0]
      });
    }

    // Create record
    const record = new Model(recordData);
    await record.save();

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(201).json({
        success: true,
        message: 'Record created successfully',
        recordId: record._id
      });
    } else {
      res.redirect(`/models/${req.params.modelName}/data?message=Record created successfully`);
    }

  } catch (error) {
    console.error('Error creating record:', error);
    
    const errorMsg = error.name === 'ValidationError' 
      ? Object.values(error.errors)[0].message
      : 'Failed to create record';
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(400).json({
        success: false,
        error: errorMsg
      });
    } else {
      res.render('models/data/form', {
        title: `Create ${req.modelDef.displayName}`,
        currentPage: 'models',
        modelDef: req.modelDef,
        recordData: req.body,
        isEdit: false,
        error: errorMsg,
        user: req.session.user
      });
    }
  }
});

// GET /models/:modelName/data/:id - View record details
router.get('/:modelName/data/:id', requireModelPermission('read'), async (req, res) => {
  try {
    const Model = req.modelDef.getModel();
    const record = await Model.findById(req.params.id)
      .populate(getPopulateFields(req.modelDef.fields));

    if (!record) {
      if (req.xhr || req.headers.accept?.includes('application/json')) {
        return res.status(404).json({
          success: false,
          error: 'Record not found'
        });
      } else {
        return res.redirect(`/models/${req.params.modelName}/data?error=Record not found`);
      }
    }

    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.json({
        success: true,
        record,
        modelDef: req.modelDef
      });
    } else {
      res.render('models/data/view', {
        title: `View ${req.modelDef.displayName}`,
        currentPage: 'models',
        modelDef: req.modelDef,
        record,
        user: req.session.user
      });
    }

  } catch (error) {
    console.error('Error viewing record:', error);
    
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      res.status(500).json({
        success: false,
        error: 'Failed to load record'
      });
    } else {
      res.redirect(`/models/${req.params.modelName}/data?error=Failed to load record`);
    }
  }
});

// GET /models/:modelName/data/:id/edit - Edit record form
router.get('/:modelName/data/:id/edit', requireModelPermission('update'), async (req, res) => {
  try {
    const Model = req.modelDef.getModel();
    const record = await Model.findById(req.params.id);

    if (!record) {
      return res.redirect(`/models/${req.params.modelName}/data?error=Record not found`);
    }

    res.render('models/data/form', {
      title: `Edit ${req.modelDef.displayName}`,
      currentPage: 'models',
      modelDef: req.modelDef,
      recordData: record,
      isEdit: true,
      user: req.session.user
    });

  } catch (error) {
    console.error('Error loading edit record form:', error);
    res.redirect(`/models/${req.params.modelName}/data?error=Failed to load edit form`);
  }
});

// PUT /models/:modelName/data/:id - Update record
router.put('/:modelName/data/:id', requireModelPermission('update'), async (req, res) => {
  try {
    const Model = req.modelDef.getModel();
    const record = await Model.findById(req.params.id);

    if (!record) {
      return res.status(404).json({
        success: false,
        error: 'Record not found'
      });
    }

    const recordData = processFormData(req.body, req.modelDef.fields);

    // Validate required fields
    const validationErrors = validateRecord(recordData, req.modelDef.fields);
    if (validationErrors.length > 0) {
      return res.status(400).json({
        success: false,
        error: validationErrors[0]
      });
    }

    // Update record
    Object.assign(record, recordData);
    await record.save();

    res.json({
      success: true,
      message: 'Record updated successfully'
    });

  } catch (error) {
    console.error('Error updating record:', error);
    
    const errorMsg = error.name === 'ValidationError' 
      ? Object.values(error.errors)[0].message
      : 'Failed to update record';
    
    res.status(400).json({
      success: false,
      error: errorMsg
    });
  }
});

// DELETE /models/:modelName/data/:id - Delete record
router.delete('/:modelName/data/:id', requireModelPermission('delete'), async (req, res) => {
  try {
    const Model = req.modelDef.getModel();
    const record = await Model.findById(req.params.id);

    if (!record) {
      return res.status(404).json({
        success: false,
        error: 'Record not found'
      });
    }

    await record.deleteOne();

    res.json({
      success: true,
      message: 'Record deleted successfully'
    });

  } catch (error) {
    console.error('Error deleting record:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete record'
    });
  }
});

// POST /models/:id/fields - Add field to model
router.post('/:id/fields', requirePermission('models', 'update'), async (req, res) => {
  try {
    const modelData = await DynamicModel.findById(req.params.id);
    
    if (!modelData) {
      return res.status(404).json({
        success: false,
        error: 'Model not found'
      });
    }

    const { name, type, required, displayName, ui } = req.body;

    if (!name || !type) {
      return res.status(400).json({
        success: false,
        error: 'Field name and type are required'
      });
    }

    // Check if field already exists
    const existingField = modelData.fields.find(f => f.name === name);
    if (existingField) {
      return res.status(400).json({
        success: false,
        error: 'Field with this name already exists'
      });
    }

    await modelData.addField({
      name,
      type,
      required: required || false,
      displayName: displayName || name,
      ui: ui || { widget: 'text' }
    });

    res.json({
      success: true,
      message: 'Field added successfully'
    });

  } catch (error) {
    console.error('Error adding field:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to add field'
    });
  }
});

// Helper functions

function getPopulateFields(fields) {
  return fields
    .filter(field => field.type === 'ObjectId' && field.ref)
    .map(field => field.name)
    .join(' ');
}

function processFormData(formData, fieldDefs) {
  const processed = {};
  
  fieldDefs.forEach(field => {
    const value = formData[field.name];
    
    if (value !== undefined && value !== '') {
      switch (field.type) {
        case 'Number':
          processed[field.name] = parseFloat(value);
          break;
        case 'Boolean':
          processed[field.name] = value === 'true' || value === true;
          break;
        case 'Date':
          processed[field.name] = new Date(value);
          break;
        case 'Array':
          if (typeof value === 'string') {
            processed[field.name] = value.split(',').map(v => v.trim());
          } else {
            processed[field.name] = Array.isArray(value) ? value : [value];
          }
          break;
        default:
          processed[field.name] = value;
      }
    }
  });
  
  return processed;
}

function validateRecord(recordData, fieldDefs) {
  const errors = [];
  
  fieldDefs.forEach(field => {
    if (field.required && (!recordData[field.name] || recordData[field.name] === '')) {
      errors.push(`${field.displayName || field.name} is required`);
    }
    
    if (field.validation) {
      const value = recordData[field.name];
      
      if (value !== undefined && value !== '') {
        if (field.validation.min !== undefined && value < field.validation.min) {
          errors.push(`${field.displayName || field.name} must be at least ${field.validation.min}`);
        }
        
        if (field.validation.max !== undefined && value > field.validation.max) {
          errors.push(`${field.displayName || field.name} must be at most ${field.validation.max}`);
        }
        
        if (field.validation.minlength !== undefined && value.length < field.validation.minlength) {
          errors.push(`${field.displayName || field.name} must be at least ${field.validation.minlength} characters`);
        }
        
        if (field.validation.maxlength !== undefined && value.length > field.validation.maxlength) {
          errors.push(`${field.displayName || field.name} must be at most ${field.validation.maxlength} characters`);
        }
        
        if (field.validation.enum && !field.validation.enum.includes(value)) {
          errors.push(`${field.displayName || field.name} must be one of: ${field.validation.enum.join(', ')}`);
        }
      }
    }
  });
  
  return errors;
}

module.exports = router;
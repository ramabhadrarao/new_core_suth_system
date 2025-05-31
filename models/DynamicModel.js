// models/DynamicModel.js - Dynamic model schema generator
const mongoose = require('mongoose');

const fieldSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  type: {
    type: String,
    required: true,
    enum: ['String', 'Number', 'Boolean', 'Date', 'ObjectId', 'Array', 'Mixed', 'Email', 'URL', 'Phone']
  },
  required: {
    type: Boolean,
    default: false
  },
  unique: {
    type: Boolean,
    default: false
  },
  index: {
    type: Boolean,
    default: false
  },
  default: mongoose.Schema.Types.Mixed,
  validation: {
    min: Number,
    max: Number,
    minlength: Number,
    maxlength: Number,
    match: String,
    enum: [String],
    custom: String // Custom validation function as string
  },
  ref: String, // For ObjectId references
  isArray: {
    type: Boolean,
    default: false
  },
  arrayType: String, // Type of array elements
  description: String,
  displayName: String,
  order: {
    type: Number,
    default: 0
  },
  // Field-level permissions
  permissions: [{
    role: { type: mongoose.Schema.Types.ObjectId, ref: 'Role' },
    access: { type: String, enum: ['read', 'write', 'none'], default: 'read' }
  }],
  // UI configuration
  ui: {
    widget: { 
      type: String, 
      enum: ['text', 'textarea', 'select', 'checkbox', 'radio', 'date', 'file', 'password', 'email', 'number'],
      default: 'text'
    },
    placeholder: String,
    helpText: String,
    hidden: { type: Boolean, default: false },
    readonly: { type: Boolean, default: false },
    options: [String] // For select, radio, checkbox widgets
  }
}, { suppressReservedKeysWarning: true });

const dynamicModelSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    match: /^[a-zA-Z][a-zA-Z0-9_]*$/
  },
  displayName: {
    type: String,
    required: true,
    trim: true
  },
  description: String,
  collectionName: {
    type: String,
    required: true,
    unique: true,
    lowercase: true
  },
  fields: [fieldSchema],
  // Model-level permissions
  permissions: [{
    role: { type: mongoose.Schema.Types.ObjectId, ref: 'Role' },
    actions: [{ type: String, enum: ['create', 'read', 'update', 'delete'] }],
    conditions: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    }
  }],
  // Indexes
  indexes: [{
    fields: mongoose.Schema.Types.Mixed,
    options: mongoose.Schema.Types.Mixed
  }],
  // Hooks/Middleware
  hooks: {
    preSave: String,
    postSave: String,
    preRemove: String,
    postRemove: String
  },
  // Virtual fields
  virtuals: [{
    name: String,
    get: String, // Function as string
    set: String  // Function as string
  }],
  // Model options
  options: {
    timestamps: { type: Boolean, default: true },
    versionKey: { type: Boolean, default: true },
    strict: { type: Boolean, default: true },
    collection: String
  },
  // UI Configuration
  ui: {
    icon: String,
    color: String,
    listView: {
      fields: [String], // Fields to show in list view
      sortBy: String,
      sortOrder: { type: String, enum: ['asc', 'desc'], default: 'desc' }
    },
    formView: {
      layout: { type: String, enum: ['default', 'tabs', 'accordion'], default: 'default' },
      groups: [{
        name: String,
        fields: [String],
        collapsible: { type: Boolean, default: false }
      }]
    }
  },
  isActive: {
    type: Boolean,
    default: true
  },
  version: {
    type: Number,
    default: 1
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
  timestamps: true
});

// Index for performance
dynamicModelSchema.index({ name: 1 });
dynamicModelSchema.index({ collectionName: 1 });
dynamicModelSchema.index({ isActive: 1 });

// Method to generate Mongoose schema
dynamicModelSchema.methods.generateMongooseSchema = function() {
  const schemaDefinition = {};
  const schemaOptions = { ...this.options };
  
  // Add default fields
  schemaDefinition._modelId = {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'DynamicModel',
    default: this._id
  };
  
  // Process fields
  this.fields.forEach(field => {
    let fieldDef = {};
    
    // Set type
    switch (field.type) {
      case 'String':
        fieldDef.type = String;
        break;
      case 'Number':
        fieldDef.type = Number;
        break;
      case 'Boolean':
        fieldDef.type = Boolean;
        break;
      case 'Date':
        fieldDef.type = Date;
        break;
      case 'ObjectId':
        fieldDef.type = mongoose.Schema.Types.ObjectId;
        if (field.ref) fieldDef.ref = field.ref;
        break;
      case 'Mixed':
        fieldDef.type = mongoose.Schema.Types.Mixed;
        break;
      case 'Email':
        fieldDef.type = String;
        fieldDef.match = /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/;
        fieldDef.lowercase = true;
        break;
      case 'URL':
        fieldDef.type = String;
        fieldDef.match = /^https?:\/\/.+/;
        break;
      case 'Phone':
        fieldDef.type = String;
        fieldDef.match = /^\+?[\d\s-()]+$/;
        break;
    }
    
    // Handle arrays
    if (field.isArray) {
      if (field.arrayType === 'ObjectId') {
        fieldDef = [{
          type: mongoose.Schema.Types.ObjectId,
          ref: field.ref
        }];
      } else {
        fieldDef = [fieldDef];
      }
    }
    
    // Add validation
    if (field.validation) {
      Object.assign(fieldDef, field.validation);
    }
    
    // Add other properties
    if (field.required) fieldDef.required = true;
    if (field.unique) fieldDef.unique = true;
    if (field.default !== undefined) fieldDef.default = field.default;
    
    schemaDefinition[field.name] = fieldDef;
  });
  
  // Create schema
  const schema = new mongoose.Schema(schemaDefinition, schemaOptions);
  
  // Add indexes
  this.indexes.forEach(index => {
    schema.index(index.fields, index.options);
  });
  
  // Add field indexes
  this.fields.forEach(field => {
    if (field.index) {
      const indexDef = {};
      indexDef[field.name] = 1;
      schema.index(indexDef);
    }
  });
  
  // Add virtuals
  this.virtuals.forEach(virtual => {
    if (virtual.get) {
      try {
        const getFunc = new Function('return ' + virtual.get)();
        schema.virtual(virtual.name).get(getFunc);
      } catch (e) {
        console.error('Error creating virtual getter:', e);
      }
    }
    
    if (virtual.set) {
      try {
        const setFunc = new Function('value', virtual.set);
        schema.virtual(virtual.name).set(setFunc);
      } catch (e) {
        console.error('Error creating virtual setter:', e);
      }
    }
  });
  
  // Add hooks
  if (this.hooks.preSave) {
    try {
      const hookFunc = new Function('next', this.hooks.preSave);
      schema.pre('save', hookFunc);
    } catch (e) {
      console.error('Error adding preSave hook:', e);
    }
  }
  
  if (this.hooks.postSave) {
    try {
      const hookFunc = new Function('doc', 'next', this.hooks.postSave);
      schema.post('save', hookFunc);
    } catch (e) {
      console.error('Error adding postSave hook:', e);
    }
  }
  
  return schema;
};

// Method to add field
dynamicModelSchema.methods.addField = function(fieldData) {
  // Check if field already exists
  const existingField = this.fields.find(f => f.name === fieldData.name);
  if (existingField) {
    throw new Error(`Field '${fieldData.name}' already exists`);
  }
  
  this.fields.push(fieldData);
  this.version += 1;
  return this.save();
};

// Method to update field
dynamicModelSchema.methods.updateField = function(fieldName, fieldData) {
  const fieldIndex = this.fields.findIndex(f => f.name === fieldName);
  if (fieldIndex === -1) {
    throw new Error(`Field '${fieldName}' not found`);
  }
  
  this.fields[fieldIndex] = { ...this.fields[fieldIndex].toObject(), ...fieldData };
  this.version += 1;
  return this.save();
};

// Method to remove field
dynamicModelSchema.methods.removeField = function(fieldName) {
  const fieldIndex = this.fields.findIndex(f => f.name === fieldName);
  if (fieldIndex === -1) {
    throw new Error(`Field '${fieldName}' not found`);
  }
  
  this.fields.splice(fieldIndex, 1);
  this.version += 1;
  return this.save();
};

// Method to get model instance
dynamicModelSchema.methods.getModel = function() {
  try {
    // Try to get existing model
    return mongoose.model(this.name);
  } catch (e) {
    // Create new model
    const schema = this.generateMongooseSchema();
    return mongoose.model(this.name, schema, this.collectionName);
  }
};

// Static method to create default models
dynamicModelSchema.statics.createDefaultModels = async function() {
  const defaultModels = [
    {
      name: 'Product',
      displayName: 'Products',
      description: 'Product management',
      collectionName: 'products',
      fields: [
        {
          name: 'name',
          type: 'String',
          required: true,
          displayName: 'Product Name',
          ui: { widget: 'text', placeholder: 'Enter product name' }
        },
        {
          name: 'description',
          type: 'String',
          displayName: 'Description',
          ui: { widget: 'textarea', placeholder: 'Enter product description' }
        },
        {
          name: 'price',
          type: 'Number',
          required: true,
          displayName: 'Price',
          validation: { min: 0 },
          ui: { widget: 'number', placeholder: 'Enter price' }
        },
        {
          name: 'category',
          type: 'String',
          displayName: 'Category',
          ui: { 
            widget: 'select', 
            options: ['Electronics', 'Clothing', 'Books', 'Home', 'Sports'] 
          }
        },
        {
          name: 'inStock',
          type: 'Boolean',
          default: true,
          displayName: 'In Stock',
          ui: { widget: 'checkbox' }
        }
      ],
      ui: {
        icon: 'package',
        color: 'blue',
        listView: {
          fields: ['name', 'price', 'category', 'inStock'],
          sortBy: 'createdAt',
          sortOrder: 'desc'
        }
      }
    }
  ];
  
  for (const modelData of defaultModels) {
    const existingModel = await this.findOne({ name: modelData.name });
    if (!existingModel) {
      await this.create(modelData);
    }
  }
};

module.exports = mongoose.model('DynamicModel', dynamicModelSchema);
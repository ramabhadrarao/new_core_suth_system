// scripts/seed.js - Database seeding script for initial setup
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
require('dotenv').config();

// Import models
const User = require('../models/User');
const Role = require('../models/Role');
const DynamicModel = require('../models/DynamicModel');

async function seedDatabase() {
  try {
    console.log('🌱 Starting database seeding...');
    
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/auth_system', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('✅ Connected to MongoDB');

    // Clear existing data (optional - comment out in production)
    if (process.env.NODE_ENV === 'development') {
      console.log('🧹 Clearing existing data...');
      await User.deleteMany({});
      await Role.deleteMany({});
      await DynamicModel.deleteMany({});
      console.log('✅ Existing data cleared');
    }

    // Create default roles
    console.log('👑 Creating default roles...');
    await Role.createDefaultRoles();
    
    const superAdminRole = await Role.findOne({ name: 'Super Admin' });
    const adminRole = await Role.findOne({ name: 'Admin' });
    const managerRole = await Role.findOne({ name: 'Manager' });
    const userRole = await Role.findOne({ name: 'User' });
    
    console.log('✅ Default roles created');

    // Create default users
    console.log('👥 Creating default users...');
    
    // Super Admin User
    const superAdmin = new User({
      username: 'superadmin',
      email: 'superadmin@example.com',
      password: 'SuperAdmin123!',
      firstName: 'Super',
      lastName: 'Admin',
      roles: [superAdminRole._id],
      attributes: {
        department: 'IT',
        location: 'Global',
        level: 'superadmin'
      },
      emailVerified: true,
      isActive: true
    });
    await superAdmin.save();
    console.log('✅ Super Admin created: superadmin@example.com / SuperAdmin123!');

    // Admin User
    const admin = new User({
      username: 'admin',
      email: 'admin@example.com',
      password: 'Admin123!',
      firstName: 'System',
      lastName: 'Administrator',
      roles: [adminRole._id],
      attributes: {
        department: 'IT',
        location: 'Head Office',
        level: 'admin'
      },
      emailVerified: true,
      isActive: true
    });
    await admin.save();
    console.log('✅ Admin created: admin@example.com / Admin123!');

    // Manager User
    const manager = new User({
      username: 'manager',
      email: 'manager@example.com',
      password: 'Manager123!',
      firstName: 'John',
      lastName: 'Manager',
      roles: [managerRole._id],
      attributes: {
        department: 'Sales',
        location: 'New York',
        level: 'manager'
      },
      emailVerified: true,
      isActive: true
    });
    await manager.save();
    console.log('✅ Manager created: manager@example.com / Manager123!');

    // Regular User
    const regularUser = new User({
      username: 'user',
      email: 'user@example.com',
      password: 'User123!',
      firstName: 'Jane',
      lastName: 'User',
      roles: [userRole._id],
      attributes: {
        department: 'Sales',
        location: 'New York',
        level: 'user',
        manager: manager._id
      },
      emailVerified: true,
      isActive: true
    });
    await regularUser.save();
    console.log('✅ Regular User created: user@example.com / User123!');

    // Demo Users with different attributes
    const users = [
      {
        username: 'alice_dev',
        email: 'alice@example.com',
        password: 'Alice123!',
        firstName: 'Alice',
        lastName: 'Developer',
        roles: [userRole._id],
        attributes: {
          department: 'Engineering',
          location: 'San Francisco',
          level: 'user',
          team: 'Frontend'
        }
      },
      {
        username: 'bob_analyst',
        email: 'bob@example.com',
        password: 'Bob123!',
        firstName: 'Bob',
        lastName: 'Analyst',
        roles: [userRole._id],
        attributes: {
          department: 'Analytics',
          location: 'Chicago',
          level: 'user',
          team: 'Data Science'
        }
      },
      {
        username: 'carol_hr',
        email: 'carol@example.com',
        password: 'Carol123!',
        firstName: 'Carol',
        lastName: 'HR',
        roles: [managerRole._id],
        attributes: {
          department: 'Human Resources',
          location: 'Head Office',
          level: 'manager'
        }
      }
    ];

    for (const userData of users) {
      const user = new User({
        ...userData,
        emailVerified: true,
        isActive: true
      });
      await user.save();
      console.log(`✅ Demo user created: ${userData.email} / ${userData.password}`);
    }

    // Create default dynamic models
    console.log('🏗️ Creating default dynamic models...');
    await DynamicModel.createDefaultModels();

    // Create additional demo models
    const customerModel = new DynamicModel({
      name: 'Customer',
      displayName: 'Customers',
      description: 'Customer management system',
      collectionName: 'customers',
      fields: [
        {
          name: 'firstName',
          type: 'String',
          required: true,
          displayName: 'First Name',
          ui: { widget: 'text', placeholder: 'Enter first name' }
        },
        {
          name: 'lastName',
          type: 'String',
          required: true,
          displayName: 'Last Name',
          ui: { widget: 'text', placeholder: 'Enter last name' }
        },
        {
          name: 'email',
          type: 'Email',
          required: true,
          unique: true,
          displayName: 'Email Address',
          ui: { widget: 'email', placeholder: 'Enter email address' }
        },
        {
          name: 'phone',
          type: 'Phone',
          displayName: 'Phone Number',
          ui: { widget: 'text', placeholder: 'Enter phone number' }
        },
        {
          name: 'company',
          type: 'String',
          displayName: 'Company',
          ui: { widget: 'text', placeholder: 'Enter company name' }
        },
        {
          name: 'status',
          type: 'String',
          displayName: 'Status',
          default: 'active',
          ui: { 
            widget: 'select', 
            options: ['active', 'inactive', 'prospect', 'lead'] 
          }
        },
        {
          name: 'tags',
          type: 'String',
          isArray: true,
          displayName: 'Tags',
          ui: { widget: 'text', placeholder: 'Enter tags (comma separated)' }
        }
      ],
      permissions: [
        {
          role: adminRole._id,
          actions: ['create', 'read', 'update', 'delete']
        },
        {
          role: managerRole._id,
          actions: ['read', 'update', 'create']
        },
        {
          role: userRole._id,
          actions: ['read'],
          conditions: { department: '${user.attributes.department}' }
        }
      ],
      ui: {
        icon: 'users',
        color: 'green',
        listView: {
          fields: ['firstName', 'lastName', 'email', 'company', 'status'],
          sortBy: 'createdAt',
          sortOrder: 'desc'
        }
      }
    });
    await customerModel.save();

    const orderModel = new DynamicModel({
      name: 'Order',
      displayName: 'Orders',
      description: 'Order management system',
      collectionName: 'orders',
      fields: [
        {
          name: 'orderNumber',
          type: 'String',
          required: true,
          unique: true,
          displayName: 'Order Number',
          ui: { widget: 'text', placeholder: 'Auto-generated' }
        },
        {
          name: 'customer',
          type: 'ObjectId',
          ref: 'Customer',
          required: true,
          displayName: 'Customer',
          ui: { widget: 'select' }
        },
        {
          name: 'amount',
          type: 'Number',
          required: true,
          displayName: 'Amount',
          validation: { min: 0 },
          ui: { widget: 'number', placeholder: 'Enter amount' }
        },
        {
          name: 'status',
          type: 'String',
          required: true,
          displayName: 'Status',
          default: 'pending',
          ui: { 
            widget: 'select', 
            options: ['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'] 
          }
        },
        {
          name: 'orderDate',
          type: 'Date',
          required: true,
          displayName: 'Order Date',
          default: 'Date.now',
          ui: { widget: 'date' }
        },
        {
          name: 'notes',
          type: 'String',
          displayName: 'Notes',
          ui: { widget: 'textarea', placeholder: 'Enter order notes' }
        }
      ],
      permissions: [
        {
          role: adminRole._id,
          actions: ['create', 'read', 'update', 'delete']
        },
        {
          role: managerRole._id,
          actions: ['read', 'update', 'create']
        },
        {
          role: userRole._id,
          actions: ['read']
        }
      ],
      ui: {
        icon: 'shopping-cart',
        color: 'orange',
        listView: {
          fields: ['orderNumber', 'customer', 'amount', 'status', 'orderDate'],
          sortBy: 'orderDate',
          sortOrder: 'desc'
        }
      }
    });
    await orderModel.save();

    console.log('✅ Default dynamic models created');

    // Update roles with additional permissions for demo models
    console.log('🔐 Setting up additional permissions...');
    
    // Add permissions for dynamic models
    await adminRole.addPermission('customers', ['create', 'read', 'update', 'delete']);
    await adminRole.addPermission('orders', ['create', 'read', 'update', 'delete']);
    await adminRole.addPermission('products', ['create', 'read', 'update', 'delete']);
    
    await managerRole.addPermission('customers', ['read', 'update', 'create']);
    await managerRole.addPermission('orders', ['read', 'update', 'create']);
    await managerRole.addPermission('products', ['read', 'update']);
    
    await userRole.addPermission('customers', ['read']);
    await userRole.addPermission('orders', ['read']);
    await userRole.addPermission('products', ['read']);

    console.log('✅ Additional permissions configured');

    console.log('\n🎉 Database seeding completed successfully!\n');
    console.log('📋 Default accounts created:');
    console.log('   Super Admin: superadmin@example.com / SuperAdmin123!');
    console.log('   Admin:       admin@example.com / Admin123!');
    console.log('   Manager:     manager@example.com / Manager123!');
    console.log('   User:        user@example.com / User123!');
    console.log('   Demo Users:  alice@example.com / Alice123!');
    console.log('                bob@example.com / Bob123!');
    console.log('                carol@example.com / Carol123!');
    console.log('\n📊 Models created:');
    console.log('   • Product (default)');
    console.log('   • Customer');
    console.log('   • Order');
    console.log('\n🚀 You can now start the application with: npm start');

  } catch (error) {
    console.error('❌ Seeding failed:', error);
    process.exit(1);
  } finally {
    await mongoose.disconnect();
    console.log('📴 Database connection closed');
    process.exit(0);
  }
}

// Run the seeding
if (require.main === module) {
  seedDatabase();
}

module.exports = seedDatabase;
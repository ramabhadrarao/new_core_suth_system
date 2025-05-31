// scripts/setup-directories.js - Create required directory structure
const fs = require('fs');
const path = require('path');

const directories = [
  'views',
  'views/auth',
  'views/dashboard',
  'views/admin',
  'views/admin/users',
  'views/admin/roles',
  'views/admin/permissions',
  'views/admin/models',
  'views/models',
  'views/models/data',
  'views/attachments',
  'uploads',
  'logs',
  'public',
  'public/css',
  'public/js',
  'public/images'
];

function createDirectories() {
  console.log('📁 Creating directory structure...');
  
  directories.forEach(dir => {
    const dirPath = path.join(__dirname, '..', dir);
    
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath, { recursive: true });
      console.log(`✅ Created: ${dir}`);
    } else {
      console.log(`⏭️  Already exists: ${dir}`);
    }
  });
  
  console.log('🎉 Directory structure created successfully!');
}

// Run if called directly
if (require.main === module) {
  createDirectories();
}

module.exports = createDirectories;
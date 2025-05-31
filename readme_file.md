# Dynamic Authentication & Authorization System

A comprehensive Node.js application with Express, EJS, MongoDB, and Tabler UI featuring dynamic models, roles, permissions, and ABAC (Attribute-Based Access Control).

## 🚀 Features

### Authentication & Security
- **Multi-factor Authentication** - JWT + Refresh Tokens + Session-based auth
- **Secure Password Management** - Bcrypt hashing, password reset, email verification
- **Account Security** - Login attempt tracking, account lockout, rate limiting
- **Security Headers** - Helmet.js with CSP, XSS protection, CSRF protection

### Authorization & Permissions
- **Dynamic Role Management** - Create, modify, and assign roles dynamically
- **ABAC (Attribute-Based Access Control)** - Fine-grained permissions based on user attributes
- **Resource-level Permissions** - Control access to specific resources and actions
- **Field-level Security** - Control access to individual fields within models
- **Hierarchical Roles** - Role inheritance with parent-child relationships

### Dynamic Models
- **Schema-less Design** - Create models and fields dynamically through the UI
- **Field Types** - Support for String, Number, Boolean, Date, ObjectId, Array, Email, URL, Phone
- **Validation Rules** - Built-in and custom validation for all field types
- **Relationships** - One-to-one, one-to-many, and many-to-many relationships
- **Indexing** - Automatic and custom database indexing

### File Management
- **Secure Upload** - File upload with virus scanning and type validation
- **Permission Control** - File-level access control and sharing
- **Versioning** - File version management and history tracking
- **Metadata** - Automatic metadata extraction and custom properties
- **Storage Options** - Local storage with S3 integration ready

### User Interface
- **Modern Design** - Clean, responsive UI built with Tabler CSS framework
- **Dashboard** - Comprehensive analytics and activity tracking
- **Search** - Global search across all models and files
- **Forms** - Dynamic form generation based on model definitions
- **Responsive** - Mobile-first design with touch-friendly interface

## 📋 Prerequisites

- Node.js 16+ and npm
- MongoDB 4.4+
- Redis (optional, for production session storage)

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd dynamic-auth-system
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment setup**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Database setup**
   ```bash
   # Start MongoDB service
   # Then seed the database
   npm run seed
   ```

5. **Start the application**
   ```bash
   # Development
   npm run dev
   
   # Production
   npm start
   ```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_ENV` | Environment mode | development |
| `PORT` | Server port | 3000 |
| `MONGODB_URI` | MongoDB connection string | mongodb://localhost:27017/auth_system |
| `SESSION_SECRET` | Session encryption key | (required) |
| `JWT_SECRET` | JWT signing key | (required) |
| `JWT_EXPIRE` | JWT expiration time | 15m |
| `REFRESH_TOKEN_SECRET` | Refresh token signing key | (required) |
| `REFRESH_TOKEN_EXPIRE` | Refresh token expiration | 7d |

### Database Seeding

The seed script creates:
- **Default Roles**: Super Admin, Admin, Manager, User
- **Demo Users** with different permission levels
- **Sample Models**: Product, Customer, Order
- **Configured Permissions** for all roles and models

Default accounts:
- Super Admin: `superadmin@example.com` / `SuperAdmin123!`
- Admin: `admin@example.com` / `Admin123!`
- Manager: `manager@example.com` / `Manager123!`
- User: `user@example.com` / `User123!`

## 🏗️ Architecture

### Project Structure
```
├── models/              # Mongoose models
│   ├── User.js         # User model with ABAC
│   ├── Role.js         # Dynamic role model
│   ├── DynamicModel.js # Schema generator
│   └── Attachment.js   # File management
├── routes/             # Express routes
│   ├── auth.js         # Authentication
│   ├── users.js        # User management
│   ├── roles.js        # Role management
│   ├── models.js       # Dynamic model CRUD
│   └── attachments.js  # File operations
├── middleware/         # Express middleware
│   └── auth.js         # Authentication & authorization
├── views/              # EJS templates
│   ├── layout.ejs      # Base layout
│   ├── auth/           # Authentication pages
│   ├── dashboard/      # Dashboard pages
│   └── admin/          # Administration pages
├── public/             # Static assets
├── uploads/            # File storage
└── scripts/            # Utility scripts
    └── seed.js         # Database seeding
```

### Security Model

#### Attribute-Based Access Control (ABAC)
```javascript
// Example permission check
const hasPermission = await user.hasPermission('customers', 'read', {
  department: user.attributes.department,
  location: user.attributes.location
});

// Example condition
{
  department: '${user.attributes.department}',
  level: { operator: 'in', value: ['manager', 'admin'] }
}
```

#### Dynamic Model Permissions
```javascript
// Model-level permissions
{
  role: roleId,
  actions: ['create', 'read', 'update', 'delete'],
  conditions: {
    department: 'Sales',
    level: { operator: 'gte', value: 5 }
  }
}

// Field-level permissions
{
  name: 'salary',
  permissions: [
    { role: hrRole, access: 'write' },
    { role: managerRole, access: 'read' },
    { role: employeeRole, access: 'none' }
  ]
}
```

## 🔐 Security Features

### Authentication
- **JWT Access Tokens** (15-minute expiry)
- **Refresh Tokens** (7-day expiry with rotation)
- **Session Management** with secure cookies
- **Password Requirements** with strength validation
- **Account Lockout** after failed attempts
- **Email Verification** for new accounts

### Authorization
- **Role-Based Access Control (RBAC)**
- **Attribute-Based Access Control (ABAC)**
- **Resource-level Permissions**
- **Dynamic Permission Assignment**
- **Condition-based Access Rules**

### Data Protection
- **Input Sanitization** against NoSQL injection
- **XSS Protection** with content security policy
- **CSRF Protection** for state-changing operations
- **Rate Limiting** per IP and endpoint
- **Secure Headers** with Helmet.js

## 📊 Usage Examples

### Creating Dynamic Models
```javascript
// Create a new model through the API
POST /models
{
  "name": "Employee",
  "displayName": "Employees",
  "fields": [
    {
      "name": "firstName",
      "type": "String",
      "required": true,
      "ui": { "widget": "text" }
    },
    {
      "name": "department",
      "type": "String",
      "ui": { 
        "widget": "select",
        "options": ["HR", "IT", "Sales", "Marketing"]
      }
    }
  ]
}
```

### Setting Up Permissions
```javascript
// Assign role-based permissions
PUT /roles/:roleId/permissions
{
  "resource": "employees",
  "actions": ["read", "update"],
  "conditions": {
    "department": "${user.attributes.department}"
  }
}
```

### File Upload with Permissions
```javascript
// Upload file with access control
POST /attachments
FormData: {
  file: [binary],
  visibility: "internal",
  permissions: [
    { role: "manager", access: "write" },
    { role: "employee", access: "read" }
  ]
}
```

## 🧪 API Endpoints

### Authentication
- `POST /auth/login` - User login
- `POST /auth/register` - User registration
- `POST /auth/logout` - User logout
- `POST /auth/refresh-token` - Refresh access token
- `POST /auth/forgot-password` - Password reset request
- `POST /auth/reset-password` - Password reset

### User Management
- `GET /users` - List users (paginated)
- `POST /users` - Create user
- `GET /users/:id` - Get user details
- `PUT /users/:id` - Update user
- `DELETE /users/:id` - Delete user
- `PUT /users/:id/roles` - Assign roles

### Role Management
- `GET /roles` - List roles
- `POST /roles` - Create role
- `PUT /roles/:id` - Update role
- `DELETE /roles/:id` - Delete role
- `PUT /roles/:id/permissions` - Set permissions

### Dynamic Models
- `GET /models` - List models
- `POST /models` - Create model
- `PUT /models/:id` - Update model
- `DELETE /models/:id` - Delete model
- `GET /models/:name/data` - Get model data
- `POST /models/:name/data` - Create record

### File Management
- `GET /attachments` - List files
- `POST /attachments` - Upload file
- `GET /attachments/:id` - Download file
- `PUT /attachments/:id` - Update file metadata
- `DELETE /attachments/:id` - Delete file

## 🚀 Deployment

### Production Setup
1. Set environment variables
2. Configure MongoDB with replica set
3. Set up Redis for session storage
4. Configure reverse proxy (nginx)
5. Set up SSL certificates
6. Configure file storage (S3)

### Docker Deployment
```dockerfile
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

### Environment-specific configurations
- **Development**: Local MongoDB, file storage
- **Staging**: Replica set, Redis sessions, S3 storage
- **Production**: High availability setup, monitoring

## 📈 Performance

### Optimization Features
- **Database Indexing** on frequently queried fields
- **Query Optimization** with proper projections
- **Caching** with Redis for sessions and frequent data
- **Compression** for HTTP responses
- **CDN Ready** for static assets

### Monitoring
- **Request Logging** with Morgan
- **Error Tracking** ready for Sentry integration
- **Performance Metrics** collection points
- **Health Check** endpoints

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: Check the `/docs` endpoint when running
- **Issues**: Create GitHub issues for bugs and feature requests
- **Community**: Join our Discord server for discussions

## 🔮 Roadmap

- [ ] GraphQL API support
- [ ] Real-time notifications with WebSockets
- [ ] Advanced workflow engine
- [ ] Multi-tenant support
- [ ] Mobile app with React Native
- [ ] Advanced analytics dashboard
- [ ] Integration marketplace
- [ ] Audit trail and compliance features
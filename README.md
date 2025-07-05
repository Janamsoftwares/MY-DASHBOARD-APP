# Dr.Net Admin Portal

A secure admin portal for Dr.Net Technology Labs with authentication, password management, and network monitoring capabilities.

## 🚀 Deployment to Railway

### Prerequisites
1. Create a [Railway](https://railway.app) account
2. Install Railway CLI: `npm install -g @railway/cli`

### Deployment Steps

1. **Login to Railway**
   ```bash
   railway login
   ```

2. **Create a new Railway project**
   ```bash
   railway new
   ```

3. **Generate password hash**
   ```bash
   cd server
   npm install
   node hash-generator.js
   ```
   Copy the generated hash for the next step.

4. **Set environment variables in Railway dashboard**
   - Go to your Railway project dashboard
   - Navigate to Variables tab
   - Add these variables:
     ```
     NODE_ENV=production
     ADMIN_USERNAME=julius
     ADMIN_PASSWORD_HASH=<your_generated_hash>
     ADMIN_EMAIL=ojwangjuli5@gmail.com
     JWT_SECRET=<generate_a_secure_random_string>
     JWT_EXPIRES_IN=24h
     MAX_LOGIN_ATTEMPTS=5
     LOCKOUT_TIME=15
     ```

5. **Deploy the application**
   ```bash
   railway up
   ```

6. **Get your deployment URL**
   ```bash
   railway domain
   ```

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `NODE_ENV` | Environment mode | `production` |
| `ADMIN_USERNAME` | Admin login username | `julius` |
| `ADMIN_PASSWORD_HASH` | Bcrypt hash of admin password | `$2a$12$...` |
| `ADMIN_EMAIL` | Admin email for password reset | `ojwangjuli5@gmail.com` |
| `JWT_SECRET` | Secret key for JWT tokens | `your_secure_secret` |
| `JWT_EXPIRES_IN` | Token expiration time | `24h` |
| `MAX_LOGIN_ATTEMPTS` | Max failed login attempts | `5` |
| `LOCKOUT_TIME` | Lockout duration in minutes | `15` |

### Login Credentials
- **Username**: `julius`
- **Password**: `drnet@2030#.`

## 🔧 Local Development

1. **Install dependencies**
   ```bash
   npm install
   cd server && npm install
   ```

2. **Generate password hash**
   ```bash
   cd server
   node hash-generator.js
   ```

3. **Set up environment variables**
   ```bash
   cp server/.env.example server/.env
   # Edit server/.env with your values
   ```

4. **Start development servers**
   ```bash
   # Terminal 1: Start backend
   npm run server:dev

   # Terminal 2: Start frontend
   npm run dev
   ```

## 🛡️ Security Features

- **Rate Limiting**: Prevents brute force attacks
- **JWT Authentication**: Secure token-based auth
- **Password Hashing**: Bcrypt with salt rounds
- **CORS Protection**: Configured for security
- **Helmet.js**: Security headers
- **Input Validation**: Server-side validation
- **Session Management**: Secure token handling

## 📱 Features

- **Secure Login**: Multi-factor authentication ready
- **Password Reset**: Email-based password recovery
- **Password Management**: Change password functionality
- **Admin Dashboard**: Network monitoring interface
- **Responsive Design**: Mobile-friendly UI
- **Real-time Feedback**: Loading states and notifications

## 🔍 API Endpoints

- `POST /api/auth/login` - User authentication
- `POST /api/auth/forgot-password` - Password reset request
- `POST /api/auth/reset-password` - Password reset confirmation
- `POST /api/auth/change-password` - Change password
- `GET /api/auth/current-user` - Get user info
- `POST /api/auth/verify` - Verify JWT token
- `POST /api/auth/logout` - User logout
- `GET /api/health` - Health check

## 📄 License

MIT License - Dr.Net Technology Labs
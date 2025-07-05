const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true
}));

// Rate limiting for login attempts
const loginLimiter = rateLimit({
  windowMs: parseInt(process.env.LOCKOUT_TIME) * 60 * 1000, // 15 minutes default
  max: parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5,
  message: {
    error: 'Too many login attempts, please try again later.',
    retryAfter: parseInt(process.env.LOCKOUT_TIME) || 15
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limiting for password reset requests
const resetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // limit each IP to 3 reset requests per windowMs
  message: {
    error: 'Too many password reset attempts, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Body parser middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// In-memory store for failed attempts and reset tokens (in production, use Redis or database)
const failedAttempts = new Map();
const resetTokens = new Map(); // Store reset tokens temporarily

// Utility function to generate password hash
async function generatePasswordHash(password) {
  const saltRounds = 12;
  return await bcrypt.hash(password, saltRounds);
}

// Utility function to verify password
async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// Generate JWT token
function generateToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '24h'
  });
}

// Generate reset token
function generateResetToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Verify JWT token middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// Simulate email sending (in production, use a real email service)
function sendPasswordResetEmail(email, resetToken) {
  // In production, integrate with services like SendGrid, Mailgun, etc.
  const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:5173'}?token=${resetToken}`;
  
  console.log('\n📧 Password Reset Email (Simulated)');
  console.log('=====================================');
  console.log(`To: ${email}`);
  console.log(`Subject: Password Reset Request - Dr.Net Admin Portal`);
  console.log(`Reset URL: ${resetUrl}`);
  console.log(`Token: ${resetToken}`);
  console.log(`Expires: ${new Date(Date.now() + 60 * 60 * 1000).toISOString()}`);
  console.log('=====================================\n');
  
  return true; // Simulate successful email sending
}

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV 
  });
});

// Login endpoint
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    const clientIP = req.ip || req.connection.remoteAddress;

    // Validate input
    if (!username || !password) {
      return res.status(400).json({ 
        error: 'Username and password are required' 
      });
    }

    // Check for too many failed attempts from this IP
    const attempts = failedAttempts.get(clientIP) || { count: 0, lastAttempt: 0 };
    const now = Date.now();
    const lockoutTime = parseInt(process.env.LOCKOUT_TIME) * 60 * 1000;

    if (attempts.count >= 5 && (now - attempts.lastAttempt) < lockoutTime) {
      return res.status(429).json({ 
        error: 'Account temporarily locked due to too many failed attempts',
        retryAfter: Math.ceil((lockoutTime - (now - attempts.lastAttempt)) / 1000 / 60)
      });
    }

    // Get admin credentials from environment
    const adminUsername = process.env.ADMIN_USERNAME;
    const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH;

    // Verify username
    if (username !== adminUsername) {
      // Record failed attempt
      failedAttempts.set(clientIP, {
        count: attempts.count + 1,
        lastAttempt: now
      });
      
      return res.status(401).json({ 
        error: 'Invalid credentials' 
      });
    }

    // Verify password
    const isValidPassword = await verifyPassword(password, adminPasswordHash);
    
    if (!isValidPassword) {
      // Record failed attempt
      failedAttempts.set(clientIP, {
        count: attempts.count + 1,
        lastAttempt: now
      });
      
      return res.status(401).json({ 
        error: 'Invalid credentials' 
      });
    }

    // Clear failed attempts on successful login
    failedAttempts.delete(clientIP);

    // Generate JWT token
    const token = generateToken({
      username: adminUsername,
      role: 'admin',
      loginTime: now
    });

    // Log successful login
    console.log(`Successful admin login from IP: ${clientIP} at ${new Date().toISOString()}`);

    res.json({
      success: true,
      token,
      user: {
        username: adminUsername,
        role: 'admin'
      },
      expiresIn: process.env.JWT_EXPIRES_IN || '24h'
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      error: 'Internal server error' 
    });
  }
});

// Forgot password endpoint
app.post('/api/auth/forgot-password', resetLimiter, async (req, res) => {
  try {
    const { username } = req.body;

    if (!username) {
      return res.status(400).json({
        error: 'Username is required'
      });
    }

    // Verify username exists
    const adminUsername = process.env.ADMIN_USERNAME;
    if (username !== adminUsername) {
      // Don't reveal if username exists or not for security
      return res.json({
        success: true,
        message: 'If the username exists, a password reset email has been sent.'
      });
    }

    // Generate reset token
    const resetToken = generateResetToken();
    const expiresAt = Date.now() + (60 * 60 * 1000); // 1 hour

    // Store reset token
    resetTokens.set(resetToken, {
      username: adminUsername,
      expiresAt,
      used: false
    });

    // Send reset email (simulated)
    const adminEmail = process.env.ADMIN_EMAIL || 'ojwangjuli5@gmail.com';
    const emailSent = sendPasswordResetEmail(adminEmail, resetToken);

    if (emailSent) {
      console.log(`Password reset requested for: ${username} at ${new Date().toISOString()}`);
      
      res.json({
        success: true,
        message: 'Password reset instructions have been sent to your email.'
      });
    } else {
      res.status(500).json({
        error: 'Failed to send reset email. Please try again later.'
      });
    }

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

// Reset password endpoint
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({
        error: 'Reset token and new password are required'
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({
        error: 'New password must be at least 8 characters long'
      });
    }

    // Verify reset token
    const resetData = resetTokens.get(token);
    if (!resetData) {
      return res.status(400).json({
        error: 'Invalid or expired reset token'
      });
    }

    // Check if token is expired
    if (Date.now() > resetData.expiresAt) {
      resetTokens.delete(token);
      return res.status(400).json({
        error: 'Reset token has expired. Please request a new one.'
      });
    }

    // Check if token was already used
    if (resetData.used) {
      return res.status(400).json({
        error: 'Reset token has already been used'
      });
    }

    // Generate new password hash
    const newPasswordHash = await generatePasswordHash(newPassword);

    // Mark token as used
    resetData.used = true;
    resetTokens.set(token, resetData);

    // In production, update the database or environment variable
    console.log('\n🔐 Password Reset Successful');
    console.log('============================');
    console.log(`User: ${resetData.username}`);
    console.log(`Time: ${new Date().toISOString()}`);
    console.log('New password hash (update your .env file):');
    console.log(`ADMIN_PASSWORD_HASH=${newPasswordHash}`);
    console.log('============================\n');

    // Clean up expired tokens
    setTimeout(() => {
      resetTokens.delete(token);
    }, 5 * 60 * 1000); // Remove after 5 minutes

    res.json({
      success: true,
      message: 'Password has been reset successfully'
    });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

// Get current user credentials endpoint
app.get('/api/auth/current-user', authenticateToken, (req, res) => {
  try {
    const adminEmail = process.env.ADMIN_EMAIL || 'ojwangjuli5@gmail.com';
    
    res.json({
      username: req.user.username,
      email: adminEmail
    });
  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

// Verify token endpoint
app.post('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({
    valid: true,
    user: req.user
  });
});

// Logout endpoint
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  // In a production app with Redis, you'd blacklist the token
  console.log(`Admin logout: ${req.user.username} at ${new Date().toISOString()}`);
  
  res.json({
    success: true,
    message: 'Logged out successfully'
  });
});

// Change password endpoint
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        error: 'Current password and new password are required'
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({
        error: 'New password must be at least 8 characters long'
      });
    }

    // Verify current password
    const currentHash = process.env.ADMIN_PASSWORD_HASH;
    const isCurrentValid = await verifyPassword(currentPassword, currentHash);

    if (!isCurrentValid) {
      return res.status(401).json({
        error: 'Current password is incorrect'
      });
    }

    // Generate new password hash
    const newHash = await generatePasswordHash(newPassword);

    // In production, update the database or environment variable
    console.log('\n🔐 Password Change Successful');
    console.log('=============================');
    console.log(`User: ${req.user.username}`);
    console.log(`Time: ${new Date().toISOString()}`);
    console.log('New password hash (update your .env file):');
    console.log(`ADMIN_PASSWORD_HASH=${newHash}`);
    console.log('=============================\n');

    res.json({
      success: true,
      message: 'Password changed successfully. Please update your environment configuration.'
    });

  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

// Protected route example
app.get('/api/admin/dashboard', authenticateToken, (req, res) => {
  res.json({
    message: 'Welcome to the admin dashboard',
    user: req.user,
    timestamp: new Date().toISOString()
  });
});

// Clean up expired reset tokens periodically
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of resetTokens.entries()) {
    if (now > data.expiresAt) {
      resetTokens.delete(token);
    }
  }
}, 10 * 60 * 1000); // Clean up every 10 minutes

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { details: err.message })
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Dr.Net Admin API Server running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔒 Security features enabled: Rate limiting, CORS, Helmet`);
  console.log(`📧 Password reset functionality: Enabled`);
  
  // Generate initial password hash if not set
  if (!process.env.ADMIN_PASSWORD_HASH) {
    console.log('\n⚠️  WARNING: No admin password hash found in environment variables!');
    console.log('Run the password hash generator to create one.');
  }
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  process.exit(0);
});

module.exports = app;
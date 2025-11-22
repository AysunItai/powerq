// server.js
require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const app = express();

// Enable CORS with proper origin restrictions
// SECURITY: Never use '*' in production - it allows any website to access your API
const allowedOrigins = process.env.FRONTEND_URL 
  ? process.env.FRONTEND_URL.split(',').map(url => url.trim())
  : ['http://localhost:3000']; // Default to localhost for development

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, Postman, or same-origin requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1 || process.env.NODE_ENV !== 'production') {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Security headers middleware
app.use((req, res, next) => {
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // Enable XSS protection
  res.setHeader('X-XSS-Protection', '1; mode=block');
  // Referrer policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  // Content Security Policy (adjust as needed for your app)
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://eng.quadrillian.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com;");
  }
  next();
});

// Parse JSON bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
// SECURITY: SESSION_SECRET must be set in production - use a strong random string
if (process.env.NODE_ENV === 'production' && !process.env.SESSION_SECRET) {
  console.error('❌ SESSION_SECRET must be set in production environment');
  process.exit(1);
}

app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  name: 'connect.sid', // Default session cookie name
  cookie: {
    secure: process.env.NODE_ENV === 'production', // Use secure cookies in production (HTTPS only)
    httpOnly: true, // Prevents JavaScript access (XSS protection)
    sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax', // CSRF protection
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    // In production, also set domain if needed:
    // domain: '.yourdomain.com'
  }
}));

// Config from .env
const QuadrillianConfig = {
    workspace_id: Number(process.env.QUAD_WORKSPACE_ID),
    workspace_secret: process.env.QUAD_WORKSPACE_SECRET,
    ai_user_id: Number(process.env.QUAD_AI_USER_ID) || undefined,
    base_url: process.env.QUAD_BASE_URL || 'https://eng.quadrillian.com'
  };

if (!QuadrillianConfig.workspace_id || !QuadrillianConfig.workspace_secret) {
  console.error('❌ QUAD_WORKSPACE_ID or QUAD_WORKSPACE_SECRET missing in .env');
  process.exit(1);
}

// In-memory user store (replace with database in production)
// For demo purposes, we'll store users in memory
const users = [
  {
    id: 'user_1',
    email: 'john@example.com',
    name: 'John Doe',
    password: bcrypt.hashSync('password123', 10) // Hashed password
  },
  {
    id: 'user_2',
    email: 'jane@example.com',
    name: 'Jane Smith',
    password: bcrypt.hashSync('password123', 10)
  }
];

// Authentication middleware
const requireAuth = (req, res, next) => {
  if (req.session && req.session.user) {
    req.user = req.session.user;
    next();
  } else {
    res.status(401).json({ error: 'Authentication required' });
  }
};

// Serve static files from /public
app.use(express.static(path.join(__dirname, 'public')));

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user by email
    const user = users.find(u => u.email === email);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Create session
    req.session.user = {
      id: user.id,
      email: user.email,
      name: user.name
    };

    res.json({ 
      success: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Logout endpoint
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.clearCookie('connect.sid');
    res.json({ success: true });
  });
});

// Get current user endpoint
app.get('/api/auth/me', (req, res) => {
  if (req.session && req.session.user) {
    res.json({ user: req.session.user });
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
});

// Protected endpoint: Generate JWT for Quadrillian chat
// SECURITY: This endpoint is protected by requireAuth middleware
// User info comes from session, NOT from request body (prevents impersonation)
app.post('/api/chat/auth', requireAuth, (req, res) => {
  try {
    // Get user from session (set by requireAuth middleware)
    // SECURITY: Never trust user data from req.body - always use authenticated session
    const user = req.user;

    const nowSeconds = Math.floor(Date.now() / 1000);

    // Build JWT payload as Quadrillian expects
    const payload = {
      workspace_id: QuadrillianConfig.workspace_id,
      external_user_id: user.id,        // Your internal user ID - ensures user isolation
      email: user.email,                 // User's email from your app
      name: user.name,                   // User's name from your app
      iat: nowSeconds,
      exp: nowSeconds + 60 * 60 * 24,    // valid for 24 hours
    };

    const token = jwt.sign(payload, QuadrillianConfig.workspace_secret, {
      algorithm: 'HS256',
    });

    // Generate user-specific topic key for chat isolation
    // Each user gets their own topic, ensuring they only see their own conversations
    const topic_external_key = `user-${user.id}`;
    // Examples: "user-user_1", "user-user_2"
    // This ensures each authenticated user sees only their own chat history

    // Return JWT and user-specific topic key
    // SECURITY: Only return minimal user info (no sensitive data)
    res.json({ 
      jwt: token,
      topic_external_key: topic_external_key,
      user: {
        id: user.id,
        email: user.email,
        name: user.name
      }
    });
  } catch (err) {
    // SECURITY: Don't expose internal error details to client
    console.error('Auth error:', err);
    res.status(500).json({ error: 'Authentication failed' });
  }
});

// Endpoint to get workspace configuration (for frontend)
// SECURITY: This is a public endpoint but only returns non-sensitive config
// Never expose workspace_secret or other sensitive credentials here
app.get('/api/chat/config', (req, res) => {
  res.json({
    workspace_id: QuadrillianConfig.workspace_id,
    ai_user_id: QuadrillianConfig.ai_user_id,
    base_url: QuadrillianConfig.base_url
    // SECURITY: workspace_secret is NEVER exposed to frontend
  });
});

// Start server
const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on port ${PORT}`);
});
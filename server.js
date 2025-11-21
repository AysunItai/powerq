// server.js
require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');

const app = express();

// Enable CORS for all routes
// In production, set FRONTEND_URL to your Render app URL
app.use(cors({
  origin: process.env.FRONTEND_URL || '*', // Allow all origins in production, restrict in production
  credentials: true
}));

// Parse JSON bodies (just in case)
app.use(express.json());

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

// Serve static files from /public
app.use(express.static(path.join(__dirname, 'public')));

/**
 * In a real app, this endpoint must be protected by your auth middleware.
 * For now, we’ll simulate a logged-in user.
 */
app.post('/api/chat/auth', (req, res) => {
  try {
    // TODO: replace this with req.user.* from your real auth
    const fakeUser = {
      id: 'user_123',                      // your internal user id
      email: 'demo.user@example.com',
      name: 'Demo User',
    };

    const nowSeconds = Math.floor(Date.now() / 1000);

    // Build JWT payload as Quadrillian expects
    const payload = {
      workspace_id: QuadrillianConfig.workspace_id,
      external_user_id: fakeUser.id,
      email: fakeUser.email,
      name: fakeUser.name,
      iat: nowSeconds,
      exp: nowSeconds + 60 * 60 * 24, // valid for 24 hours
    };

    const token = jwt.sign(payload, QuadrillianConfig.workspace_secret, {
      algorithm: 'HS256',
    });

    // Return JSON { jwt: "..." }
    res.json({ jwt: token });
  } catch (err) {
    console.error('Auth error:', err);
    res.status(500).json({ error: 'Authentication failed' });
  }
});

// Endpoint to get workspace configuration (for frontend)
app.get('/api/chat/config', (req, res) => {
  res.json({
    workspace_id: QuadrillianConfig.workspace_id,
    ai_user_id: QuadrillianConfig.ai_user_id,
    base_url: QuadrillianConfig.base_url
  });
});

// Start server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`✅ Server running on http://localhost:${port}`);
});

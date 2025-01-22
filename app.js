require('dotenv').config();
const express = require('express');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false
}));

// Routes
app.get('/', (req, res) => {
  res.render('index');
});

// Native Login Form
app.get('/login', (req, res) => {
  res.render('login');
});

// Native Login Handler
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // For demo, just create a token
  const token = jwt.sign(
    { 
      name: username,
      email: username,
      username: username
    },
    process.env.JWT_SECRET || 'your-jwt-secret',
    { expiresIn: '1h' }
  );

  res.json({ token });
});

// Auth0 Login
app.get('/auth0-login', (req, res) => {
  const auth0Domain = process.env.AUTH0_DOMAIN;
  const clientId = process.env.AUTH0_CLIENT_ID;
  const redirectUri = `${process.env.APP_URL}/callback`;
  const scope = 'openid profile email offline_access';

  const url = `https://${auth0Domain}/authorize?` +
    `response_type=code&` +
    `client_id=${clientId}&` +
    `redirect_uri=${redirectUri}&` +
    `scope=${scope}`;

  res.redirect(url);
});

// Auth0 Callback
app.get('/callback', async (req, res) => {
  const code = req.query.code;
  
  // Exchange code for tokens
  const tokenResponse = await fetch(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      client_id: process.env.AUTH0_CLIENT_ID,
      client_secret: process.env.AUTH0_CLIENT_SECRET,
      code,
      redirect_uri: `${process.env.APP_URL}/callback`
    })
  });

  const tokens = await tokenResponse.json();
  res.render('callback', { tokens: JSON.stringify(tokens) });
});

// Token Refresh
app.post('/refresh-token', async (req, res) => {
  const { refresh_token } = req.body;

  if (!refresh_token) {
    return res.status(400).json({ error: 'Refresh token required' });
  }

  try {
    const response = await fetch(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'refresh_token',
        client_id: process.env.AUTH0_CLIENT_ID,
        client_secret: process.env.AUTH0_CLIENT_SECRET,
        refresh_token
      })
    });

    const tokens = await response.json();
    res.json(tokens);
  } catch (error) {
    res.status(500).json({ error: 'Failed to refresh token' });
  }
});

// Add this route with the other routes
app.get('/dashboard', (req, res) => {
  res.render('dashboard', {
    auth0Domain: process.env.AUTH0_DOMAIN,
    clientId: process.env.AUTH0_CLIENT_ID,
    appMode: process.env.APP_MODE || 'native'
  });
});

// Add a new endpoint for token exchange
app.post('/exchange-token', async (req, res) => {
  try {
    const { native_token } = req.body;

    // Create URLSearchParams for x-www-form-urlencoded format
    const params = new URLSearchParams();
    params.append('grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange');
    params.append('scopes', 'openid urn:shell:idp-migraton');
    params.append('subject_token_type', 'urn:shell:idp-migraton');
    params.append('subject_token', native_token);
    params.append('client_id', process.env.AUTH0_CLIENT_ID);
    params.append('client_secret', process.env.AUTH0_CLIENT_SECRET);

    const response = await fetch(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString()
    });

    const tokens = await response.json();
    if (!response.ok) {
      throw new Error(tokens.error_description || 'Failed to exchange token');
    }

    res.json(tokens);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 
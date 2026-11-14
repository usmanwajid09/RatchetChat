/**
 * RatchetChat - Authentication Routes
 */

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../database.js');
const { requireAuth, JWT_SECRET } = require('../middleware/authMiddleware.js');

// Register a new user
router.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password || username.trim().length < 3 || password.length < 6) {
      return res.status(400).json({ error: 'Username (min 3 chars) and password (min 6 chars) are required.' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const user = await db.createUser(username.trim(), passwordHash);
    const token = jwt.sign({ username: user.username, id: user.id }, JWT_SECRET, { expiresIn: '7d' });

    db.addAuditLog('USER_REGISTERED', { username: user.username });

    return res.status(201).json({
      message: 'User registered successfully',
      user: { username: user.username },
      token,
    });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required.' });
    }

    const user = await db.findUserByUsername(username.trim());
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const token = jwt.sign({ username: user.username, id: user.id }, JWT_SECRET, { expiresIn: '7d' });
    db.addAuditLog('USER_LOGIN', { username: user.username });

    return res.json({
      message: 'Login successful',
      user: { username: user.username },
      token,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// List all registered contacts
router.get('/users', requireAuth, async (req, res) => {
  try {
    const users = await db.listUsers();
    return res.json({ users });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Get current user profile
router.get('/me', requireAuth, async (req, res) => {
  return res.json({ user: req.user });
});

module.exports = router;


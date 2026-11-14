/**
 * RatchetChat - Messages Routing (Zero-Knowledge Ciphertext Mailbox)
 */

const express = require('express');
const router = express.Router();
const db = require('../database.js');
const { requireAuth } = require('../middleware/authMiddleware.js');

// Send message via HTTP fallback (queues in DB for offline delivery)
router.post('/send', requireAuth, async (req, res) => {
  try {
    const sender = req.user.username;
    const { recipient, payload } = req.body;

    if (!recipient || !payload || !payload.ciphertextHex || !payload.ivHex) {
      return res.status(400).json({ error: 'Invalid message payload. Must include ciphertextHex and ivHex.' });
    }

    const queued = await db.queueMessage(sender, recipient, payload);
    return res.status(201).json({
      message: 'Ciphertext queued successfully for offline recipient',
      messageId: queued.id,
      timestamp: queued.timestamp,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Fetch queued messages for authenticated user
router.get('/pending', requireAuth, async (req, res) => {
  try {
    const username = req.user.username;
    const messages = await db.getPendingMessages(username);
    return res.json({
      count: messages.length,
      messages,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

module.exports = router;


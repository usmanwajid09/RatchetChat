/**
 * RatchetChat - Admin & Attack Toolkit Routes
 */

const express = require('express');
const router = express.Router();
const db = require('../database.js');

// Relay Inspector: view packets currently traversing the server
router.get('/relay-inspector', (req, res) => {
  const auditLogs = db.getAuditLogs(100);
  const stats = db.getStats();
  return res.json({
    stats,
    packets: auditLogs,
  });
});

// Database Dump: allows inspection of raw stored data
router.get('/database-dump', (req, res) => {
  // Returns raw stored records. Shows that stored messages are 100% encrypted blobs.
  return res.json({
    storedPrekeys: db.memoryDb.prekeys,
    queuedCiphertexts: db.memoryDb.messages.map((m) => ({
      id: m.id,
      sender: m.sender,
      recipient: m.recipient,
      timestamp: m.timestamp,
      delivered: m.delivered,
      ciphertextSample: m.payload && m.payload.ciphertextHex ? m.payload.ciphertextHex.slice(0, 32) + '... (AES-256-GCM)' : null,
      iv: m.payload ? m.payload.ivHex : null,
      ratchetPub: m.payload && m.payload.header ? m.payload.header.dhRatchetPubHex : null,
      counter: m.payload && m.payload.header ? m.payload.header.n : null,
      plaintextVisible: false,
    })),
  });
});

// Configure MitM Attack parameters
router.post('/mitm-toggle', (req, res) => {
  const { active, attackerUsername, targetRecipient, spoofedPrekeyBundle } = req.body;
  const updated = db.setMitmSettings({
    active: !!active,
    attackerUsername: attackerUsername || 'mallory',
    targetRecipient: targetRecipient || '',
    spoofedPrekeyBundle: spoofedPrekeyBundle || null,
  });

  db.addAuditLog('MITM_CONFIGURATION_UPDATED', {
    active: updated.active,
    targetRecipient: updated.targetRecipient,
    attacker: updated.attackerUsername,
  });

  return res.json({
    message: 'MitM settings updated',
    settings: updated,
  });
});

// Get system stats
router.get('/system-stats', (req, res) => {
  return res.json(db.getStats());
});

module.exports = router;


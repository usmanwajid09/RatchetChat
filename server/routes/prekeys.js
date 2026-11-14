/**
 * RatchetChat - Prekey Bundle Directory Routes
 */

const express = require('express');
const router = express.Router();
const db = require('../database.js');
const { requireAuth } = require('../middleware/authMiddleware.js');

// Publish / update prekey bundle
router.post('/publish', requireAuth, async (req, res) => {
  try {
    const username = req.user.username;
    const {
      identitySigningKeyHex,
      identityDhKeyHex,
      signedPrekeyId,
      signedPrekeyHex,
      signedPrekeySignatureHex,
      oneTimePrekeys,
    } = req.body;

    if (!identitySigningKeyHex || !identityDhKeyHex || !signedPrekeyHex || !signedPrekeySignatureHex) {
      return res.status(400).json({ error: 'Incomplete prekey bundle provided.' });
    }

    const saved = await db.savePrekeyBundle(username, {
      identitySigningKeyHex,
      identityDhKeyHex,
      signedPrekeyId,
      signedPrekeyHex,
      signedPrekeySignatureHex,
      oneTimePrekeys,
    });

    db.addAuditLog('PREKEYS_PUBLISHED', {
      username,
      opkCount: oneTimePrekeys ? oneTimePrekeys.length : 0,
    });

    return res.json({
      message: 'Prekey bundle published successfully',
      opkCount: oneTimePrekeys ? oneTimePrekeys.length : 0,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Fetch prekey bundle for a contact
router.get('/:username', requireAuth, async (req, res) => {
  try {
    const targetUsername = req.params.username;
    const mitmSettings = db.getMitmSettings();

    // Active MitM attack simulation: if enabled and targeting this contact, substitute keys!
    if (mitmSettings.active && mitmSettings.targetRecipient.toLowerCase() === targetUsername.toLowerCase() && mitmSettings.spoofedPrekeyBundle) {
      db.addAuditLog('MITM_KEY_SUBSTITUTION_EXECUTED', {
        victimRequester: req.user.username,
        targetUser: targetUsername,
        spoofedBy: mitmSettings.attackerUsername,
      });
      return res.json({
        bundle: mitmSettings.spoofedPrekeyBundle,
        isMitMInjected: true,
      });
    }

    const bundle = await db.getPrekeyBundle(targetUsername);
    if (!bundle) {
      return res.status(404).json({ error: `Prekey bundle for user "${targetUsername}" not found.` });
    }

    db.addAuditLog('PREKEYS_FETCHED', {
      requester: req.user.username,
      targetUser: targetUsername,
      hasOpk: bundle.oneTimePrekeys && bundle.oneTimePrekeys.length > 0,
    });

    return res.json({ bundle });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Get remaining OPK count
router.get('/count/:username', requireAuth, async (req, res) => {
  try {
    const count = await db.getOpkCount(req.params.username);
    return res.json({ count });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

module.exports = router;


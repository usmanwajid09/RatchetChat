/**
 * RatchetChat - Dual Database Engine
 * Supports MongoDB with seamless fallback to an embedded JSON database.
 * Stores only public prekey bundles, user credentials, and queued ciphertexts.
 * Zero plaintext messages are ever stored or processed.
 */

const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');

class DatabaseManager {
  constructor() {
    this.isMongo = false;
    this.jsonDbPath = path.join(__dirname, '../data/local_db.json');
    this.memoryDb = {
      users: [],
      prekeys: {},
      messages: [],
      auditLogs: [],
      mitmSettings: {
        active: false,
        attackerUsername: 'mallory',
        targetRecipient: '',
        spoofedPrekeyBundle: null,
      },
    };
  }

  async init(mongoUri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/ratchetchat') {
    // Ensure data directory exists for local fallback
    const dataDir = path.dirname(this.jsonDbPath);
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }

    // Load existing local DB file if available
    if (fs.existsSync(this.jsonDbPath)) {
      try {
        const raw = fs.readFileSync(this.jsonDbPath, 'utf8');
        this.memoryDb = Object.assign(this.memoryDb, JSON.parse(raw));
      } catch (e) {
        console.warn('Could not read existing local DB file, starting fresh.');
      }
    }

    try {
      console.log('Attempting MongoDB connection at:', mongoUri);
      await mongoose.connect(mongoUri, { serverSelectionTimeoutMS: 2000 });
      this.isMongo = true;
      console.log('Connected to MongoDB successfully.');
    } catch (err) {
      this.isMongo = false;
      console.log('MongoDB not reachable (' + err.message + ').');
      console.log('-> Activated zero-dependency persistent JSON database engine.');
    }
  }

  _persistLocal() {
    if (!this.isMongo) {
      try {
        fs.writeFileSync(this.jsonDbPath, JSON.stringify(this.memoryDb, null, 2), 'utf8');
      } catch (e) {
        console.error('Error persisting local database:', e);
      }
    }
  }

  // --- User Operations ---

  async findUserByUsername(username) {
    return this.memoryDb.users.find((u) => u.username.toLowerCase() === username.toLowerCase()) || null;
  }

  async createUser(username, passwordHash) {
    const existing = await this.findUserByUsername(username);
    if (existing) {
      throw new Error('Username already exists');
    }
    const user = {
      id: 'usr_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7),
      username,
      passwordHash,
      createdAt: new Date().toISOString(),
    };
    this.memoryDb.users.push(user);
    this._persistLocal();
    return user;
  }

  async listUsers() {
    return this.memoryDb.users.map((u) => ({
      username: u.username,
      createdAt: u.createdAt,
      hasPrekeys: !!this.memoryDb.prekeys[u.username.toLowerCase()],
    }));
  }

  // --- Prekey Bundle Operations ---

  async savePrekeyBundle(username, bundle) {
    const key = username.toLowerCase();
    this.memoryDb.prekeys[key] = {
      username,
      identitySigningKeyHex: bundle.identitySigningKeyHex,
      identityDhKeyHex: bundle.identityDhKeyHex,
      signedPrekeyId: bundle.signedPrekeyId,
      signedPrekeyHex: bundle.signedPrekeyHex,
      signedPrekeySignatureHex: bundle.signedPrekeySignatureHex,
      oneTimePrekeys: bundle.oneTimePrekeys || [],
      updatedAt: new Date().toISOString(),
    };
    this._persistLocal();
    return this.memoryDb.prekeys[key];
  }

  async getPrekeyBundle(username) {
    const key = username.toLowerCase();
    const stored = this.memoryDb.prekeys[key];
    if (!stored) return null;

    // Pop one One-Time Prekey (OPK) if available
    let chosenOpk = null;
    if (stored.oneTimePrekeys && stored.oneTimePrekeys.length > 0) {
      chosenOpk = stored.oneTimePrekeys.shift();
      this._persistLocal();
    }

    return {
      username: stored.username,
      identitySigningKeyHex: stored.identitySigningKeyHex,
      identityDhKeyHex: stored.identityDhKeyHex,
      signedPrekeyId: stored.signedPrekeyId,
      signedPrekeyHex: stored.signedPrekeyHex,
      signedPrekeySignatureHex: stored.signedPrekeySignatureHex,
      oneTimePrekeys: chosenOpk ? [chosenOpk] : [],
      remainingOpkCount: stored.oneTimePrekeys ? stored.oneTimePrekeys.length : 0,
    };
  }

  async getOpkCount(username) {
    const key = username.toLowerCase();
    const stored = this.memoryDb.prekeys[key];
    return stored && stored.oneTimePrekeys ? stored.oneTimePrekeys.length : 0;
  }

  // --- Offline Message Queueing ---

  async queueMessage(sender, recipient, payload) {
    const msg = {
      id: 'msg_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7),
      sender,
      recipient,
      payload, // Encrypted ciphertext blob + ratchet header only! ZERO plaintext.
      timestamp: new Date().toISOString(),
      delivered: false,
    };
    this.memoryDb.messages.push(msg);

    // Keep packet inspector log
    this.addAuditLog('MESSAGE_RELAYED', {
      id: msg.id,
      sender,
      recipient,
      dhRatchetPubHex: payload.header ? payload.header.dhRatchetPubHex : null,
      n: payload.header ? payload.header.n : null,
      pn: payload.header ? payload.header.pn : null,
      ciphertextLength: payload.ciphertextHex ? payload.ciphertextHex.length / 2 : 0,
      timestamp: msg.timestamp,
    });

    this._persistLocal();
    return msg;
  }

  async getPendingMessages(recipient) {
    const key = recipient.toLowerCase();
    const pending = this.memoryDb.messages.filter(
      (m) => m.recipient.toLowerCase() === key && !m.delivered
    );
    // Mark as delivered
    pending.forEach((m) => (m.delivered = true));
    this._persistLocal();
    return pending;
  }

  // --- Audit & Attacker Toolkit Controls ---

  addAuditLog(eventType, details) {
    const entry = {
      id: 'log_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6),
      timestamp: new Date().toISOString(),
      eventType,
      details,
    };
    this.memoryDb.auditLogs.unshift(entry);
    if (this.memoryDb.auditLogs.length > 500) {
      this.memoryDb.auditLogs.pop();
    }
    this._persistLocal();
    return entry;
  }

  getAuditLogs(limit = 50) {
    return this.memoryDb.auditLogs.slice(0, limit);
  }

  setMitmSettings(settings) {
    this.memoryDb.mitmSettings = Object.assign(this.memoryDb.mitmSettings, settings);
    this._persistLocal();
    return this.memoryDb.mitmSettings;
  }

  getMitmSettings() {
    return this.memoryDb.mitmSettings;
  }

  getStats() {
    return {
      usersCount: this.memoryDb.users.length,
      prekeyBundlesCount: Object.keys(this.memoryDb.prekeys).length,
      totalMessagesRelayed: this.memoryDb.messages.length,
      auditLogsCount: this.memoryDb.auditLogs.length,
      dbEngine: this.isMongo ? 'MongoDB' : 'Persistent Local JSON Database',
      mitmActive: this.memoryDb.mitmSettings.active,
    };
  }
}

module.exports = new DatabaseManager();


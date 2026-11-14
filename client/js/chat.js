/**
 * RatchetChat - Client Chat & Cryptographic Session Coordinator
 *
 * Connects the UI, Network, and Cryptographic Engine:
 * - Asynchronous X3DH Key Agreement
 * - Double Ratchet state management
 * - Safety Number generation & verification
 * - Seamless switching between Secure Mode and Weak Mode for attack demos
 */

const ChatManager = (function () {
  let currentUser = null;
  let activeContact = null;
  let weakMode = false;

  const keyStore = new RatchetKeyStore.KeyStore('ratchetchat_');
  const sessions = new Map(); // contactUsername -> DoubleRatchetSession
  const safetyNumbers = new Map(); // contactUsername -> { numericString, formatted, verified, alert }
  const chatHistory = new Map(); // contactUsername -> Array of messages
  const contactsList = new Map(); // contactUsername -> { username, online, hasPrekeys }
  const messageListeners = [];
  const stateChangeListeners = [];

  // Helper serialization for Uint8Arrays in session persistence
  function serializeKeys(obj) {
    return JSON.stringify(obj, (key, value) => {
      if (value instanceof Uint8Array) {
        return { __uint8: true, hex: RatchetPrimitives.toHex(value) };
      }
      return value;
    });
  }

  function deserializeKeys(jsonStr) {
    return JSON.parse(jsonStr, (key, value) => {
      if (value && value.__uint8 && value.hex) {
        return RatchetPrimitives.fromHex(value.hex);
      }
      return value;
    });
  }

  /**
   * Initializes user identity and prekey bundle upon login/registration.
   */
  async function initUser(userData, token) {
    currentUser = userData;
    API.setToken(token);

    // Retrieve or generate persistent cryptographic keys
    let storedKeys = keyStore.get(`keys_${currentUser.username}`);
    if (!storedKeys) {
      console.log('[Crypto] Generating new X3DH Prekey Bundle for:', currentUser.username);
      const prekeyBundle = RatchetX3DH.generatePrekeyBundle(20);
      storedKeys = {
        identityKeys: {
          signing: {
            privateKey: RatchetPrimitives.toHex(prekeyBundle.identityKeys.signing.privateKey),
            publicKey: RatchetPrimitives.toHex(prekeyBundle.identityKeys.signing.publicKey),
          },
          dh: {
            privateKey: RatchetPrimitives.toHex(prekeyBundle.identityKeys.dh.privateKey),
            publicKey: RatchetPrimitives.toHex(prekeyBundle.identityKeys.dh.publicKey),
          },
        },
        signedPrekey: {
          id: prekeyBundle.signedPrekey.id,
          privateKey: RatchetPrimitives.toHex(prekeyBundle.signedPrekey.privateKey),
          publicKey: RatchetPrimitives.toHex(prekeyBundle.signedPrekey.publicKey),
        },
        oneTimePrekeys: prekeyBundle.oneTimePrekeys.map((k) => ({
          id: k.id,
          privateKey: RatchetPrimitives.toHex(k.privateKey),
          publicKey: RatchetPrimitives.toHex(k.publicKey),
        })),
        publicBundle: prekeyBundle.publicBundle,
      };
      keyStore.set(`keys_${currentUser.username}`, storedKeys);

      // Publish bundle to relay server
      await API.publishPrekeys(storedKeys.publicBundle);
    } else {
      console.log('[Crypto] Loaded existing cryptographic keys for:', currentUser.username);
    }

    // Connect WebSocket
    ChatSocket.connect(token);
    setupSocketHandlers();

    // Load registered contacts
    await refreshContacts();

    // Check for offline messages
    await checkOfflineMessages();

    notifyStateChange();
    return currentUser;
  }

  function getStoredUserKeys() {
    if (!currentUser) return null;
    const stored = keyStore.get(`keys_${currentUser.username}`);
    if (!stored) return null;
    return {
      identityKeys: {
        signing: {
          privateKey: RatchetPrimitives.fromHex(stored.identityKeys.signing.privateKey),
          publicKey: RatchetPrimitives.fromHex(stored.identityKeys.signing.publicKey),
        },
        dh: {
          privateKey: RatchetPrimitives.fromHex(stored.identityKeys.dh.privateKey),
          publicKey: RatchetPrimitives.fromHex(stored.identityKeys.dh.publicKey),
        },
      },
      signedPrekey: {
        id: stored.signedPrekey.id,
        privateKey: RatchetPrimitives.fromHex(stored.signedPrekey.privateKey),
        publicKey: RatchetPrimitives.fromHex(stored.signedPrekey.publicKey),
      },
      oneTimePrekeys: stored.oneTimePrekeys.map((k) => ({
        id: k.id,
        privateKey: RatchetPrimitives.fromHex(k.privateKey),
        publicKey: RatchetPrimitives.fromHex(k.publicKey),
      })),
      publicBundle: stored.publicBundle,
    };
  }

  function setupSocketHandlers() {
    ChatSocket.on('message', async (messageData) => {
      await handleIncomingMessage(messageData);
    });

    ChatSocket.on('pending_messages', async (messages) => {
      for (const msg of messages) {
        await handleIncomingMessage(msg);
      }
    });

    ChatSocket.on('presence', (onlineUsers) => {
      const lower = onlineUsers.map((u) => u.toLowerCase());
      contactsList.forEach((val, name) => {
        val.online = lower.includes(name.toLowerCase());
      });
      notifyStateChange();
    });
  }

  async function refreshContacts() {
    try {
      const res = await API.getUsers();
      if (res && res.users) {
        res.users.forEach((u) => {
          if (currentUser && u.username.toLowerCase() === currentUser.username.toLowerCase()) {
            return; // Don't list ourselves
          }
          const existing = contactsList.get(u.username) || {};
          contactsList.set(u.username, {
            ...existing,
            username: u.username,
            hasPrekeys: u.hasPrekeys,
            online: existing.online || false,
          });
        });
      }
      notifyStateChange();
    } catch (e) {
      console.warn('Could not refresh contacts:', e);
    }
  }

  async function checkOfflineMessages() {
    try {
      const res = await API.fetchPendingMessages();
      if (res && res.messages) {
        for (const msg of res.messages) {
          await handleIncomingMessage(msg);
        }
      }
    } catch (e) {
      console.warn('Could not check offline messages:', e);
    }
  }

  /**
   * Establishes or retrieves the Double Ratchet session for a given contact.
   */
  async function getOrCreateSession(contactUsername, isInitiator = false) {
    const contactKey = contactUsername.toLowerCase();
    if (sessions.has(contactKey)) {
      return sessions.get(contactKey);
    }

    if (!isInitiator) {
      return null;
    }

    // Alice initiates X3DH handshake with Bob
    console.log(`[X3DH] Initiating key agreement with ${contactUsername}...`);
    const bundleRes = await API.fetchPrekeyBundle(contactUsername);
    const bobBundle = bundleRes.bundle;
    const userKeys = getStoredUserKeys();

    const x3dhResult = await RatchetX3DH.aliceInitiate(userKeys.identityKeys, bobBundle, weakMode);

    // Compute Safety Number
    const safety = await RatchetSafetyNumber.computeSafetyNumber(
      userKeys.identityKeys.signing.publicKey,
      bobBundle.identitySigningKeyHex
    );
    safetyNumbers.set(contactKey, {
      ...safety,
      verified: false,
      contactIdentityKeyHex: bobBundle.identitySigningKeyHex,
      isMitMInjected: !!bundleRes.isMitMInjected,
    });

    // Create Double Ratchet session
    const session = new RatchetDoubleRatchet.DoubleRatchetSession({
      sharedMasterSecret: x3dhResult.sharedMasterSecret,
      theirDhPublicKey: RatchetPrimitives.fromHex(bobBundle.signedPrekeyHex),
      isInitiator: true,
      associatedData: x3dhResult.associatedData,
    });

    session._initialX3dhData = {
      aliceIdentitySigningPubHex: RatchetPrimitives.toHex(x3dhResult.aliceIdentitySigningPub),
      aliceIdentityDhPubHex: RatchetPrimitives.toHex(x3dhResult.aliceIdentityDhPub),
      ephemeralPublicKeyHex: RatchetPrimitives.toHex(x3dhResult.ephemeralPublicKey),
      usedOpkId: x3dhResult.usedOpkId,
    };

    sessions.set(contactKey, session);
    notifyStateChange();
    return session;
  }

  /**
   * Send an end-to-end encrypted message to a contact.
   */
  async function sendMessage(contactUsername, plaintext) {
    if (!contactUsername || !plaintext.trim()) return;
    const contactKey = contactUsername.toLowerCase();

    let session = sessions.get(contactKey);
    let isInitialMessage = false;

    if (!session) {
      isInitialMessage = true;
      session = await getOrCreateSession(contactUsername, true);
    }

    // Encrypt using Double Ratchet
    const encrypted = await session.encrypt(plaintext);

    const payload = {
      header: encrypted.header,
      ivHex: encrypted.ivHex,
      ciphertextHex: encrypted.ciphertextHex,
    };

    // If initial message, attach X3DH handshake header
    if (isInitialMessage && session._initialX3dhData) {
      payload.x3dh = session._initialX3dhData;
      session._initialX3dhData = null; // Sent once
    }

    // Transmit over WebSocket or HTTP fallback
    try {
      if (ChatSocket.isConnected()) {
        await ChatSocket.sendMessage(contactUsername, payload);
      } else {
        await API.sendOfflineMessage(contactUsername, payload);
      }
    } catch (e) {
      console.warn('Socket relay failed, attempting HTTP queue fallback:', e);
      await API.sendOfflineMessage(contactUsername, payload);
    }

    // Record in local chat history
    const history = chatHistory.get(contactKey) || [];
    const msgRecord = {
      id: 'out_' + Date.now(),
      sender: currentUser.username,
      recipient: contactUsername,
      text: plaintext,
      timestamp: new Date().toISOString(),
      rawPayload: payload,
      isOutgoing: true,
      ratchetMetrics: session.getStatus(),
    };
    history.push(msgRecord);
    chatHistory.set(contactKey, history);

    notifyMessage(msgRecord);
    notifyStateChange();
    return msgRecord;
  }

  /**
   * Process an incoming encrypted message.
   */
  async function handleIncomingMessage(messageData) {
    const sender = messageData.sender;
    const senderKey = sender.toLowerCase();
    const payload = messageData.payload;

    let session = sessions.get(senderKey);

    try {
      // 1. If payload contains X3DH handshake header and we have no session, initialize Bob's side
      if (payload.x3dh) {
        console.log(`[X3DH] Received initial handshake from ${sender}`);
        const userKeys = getStoredUserKeys();
        const x3dhResult = await RatchetX3DH.bobReceive(userKeys, payload.x3dh);

        session = new RatchetDoubleRatchet.DoubleRatchetSession({
          sharedMasterSecret: x3dhResult.sharedMasterSecret,
          ourDhKeyPair: userKeys.signedPrekey,
          isInitiator: false,
          associatedData: x3dhResult.associatedData,
        });
        sessions.set(senderKey, session);

        // Compute Safety Number
        const safety = await RatchetSafetyNumber.computeSafetyNumber(
          userKeys.identityKeys.signing.publicKey,
          payload.x3dh.aliceIdentitySigningPubHex
        );

        // Check if sender identity key changed (MITM / Key Replacement alert)
        const prevSafety = safetyNumbers.get(senderKey);
        let alert = false;
        if (prevSafety && prevSafety.contactIdentityKeyHex !== payload.x3dh.aliceIdentitySigningPubHex) {
          alert = true;
          console.warn(`[SECURITY WARNING] Identity key changed for ${sender}!`);
        }

        safetyNumbers.set(senderKey, {
          ...safety,
          verified: false,
          contactIdentityKeyHex: payload.x3dh.aliceIdentitySigningPubHex,
          alert,
        });
      }

      if (!session) {
        throw new Error(`Cannot decrypt: No active cryptographic session with ${sender}`);
      }

      // 2. Decrypt message via Double Ratchet
      const decryptedPlaintext = await session.decrypt(payload);

      const history = chatHistory.get(senderKey) || [];
      const msgRecord = {
        id: messageData.id || 'in_' + Date.now(),
        sender,
        recipient: currentUser.username,
        text: decryptedPlaintext,
        timestamp: messageData.timestamp || new Date().toISOString(),
        rawPayload: payload,
        isOutgoing: false,
        ratchetMetrics: session.getStatus(),
        status: 'DECRYPTED_SUCCESSFULLY',
      };
      history.push(msgRecord);
      chatHistory.set(senderKey, history);

      notifyMessage(msgRecord);
      notifyStateChange();
    } catch (err) {
      console.error('[Crypto Decryption Error]:', err);
      const history = chatHistory.get(senderKey) || [];
      const msgRecord = {
        id: messageData.id || 'err_' + Date.now(),
        sender,
        recipient: currentUser.username,
        text: `[DECRYPTION FAILED: ${err.message}]`,
        timestamp: messageData.timestamp || new Date().toISOString(),
        rawPayload: payload,
        isOutgoing: false,
        error: err.message,
        status: 'FAILED',
      };
      history.push(msgRecord);
      chatHistory.set(senderKey, history);

      notifyMessage(msgRecord);
      notifyStateChange();
    }
  }

  function setWeakMode(enabled) {
    weakMode = !!enabled;
    console.log(`[RatchetChat] Security Mode: ${weakMode ? 'WEAK / VULNERABLE MODE' : 'SECURE MODE'}`);
    notifyStateChange();
  }

  function isWeakMode() {
    return weakMode;
  }

  function setActiveContact(username) {
    activeContact = username;
    notifyStateChange();
  }

  function getActiveContact() {
    return activeContact;
  }

  function getCurrentUser() {
    return currentUser;
  }

  function getContacts() {
    return Array.from(contactsList.values());
  }

  function getChatHistory(contactUsername) {
    if (!contactUsername) return [];
    return chatHistory.get(contactUsername.toLowerCase()) || [];
  }

  function getSessionMetrics(contactUsername) {
    if (!contactUsername) return null;
    const session = sessions.get(contactUsername.toLowerCase());
    return session ? session.getStatus() : null;
  }

  function getSafetyNumber(contactUsername) {
    if (!contactUsername) return null;
    return safetyNumbers.get(contactUsername.toLowerCase()) || null;
  }

  function verifySafetyNumber(contactUsername, isVerified) {
    const key = contactUsername.toLowerCase();
    const safety = safetyNumbers.get(key);
    if (safety) {
      safety.verified = !!isVerified;
      safety.alert = false; // Acknowledged
      notifyStateChange();
    }
  }

  function onMessage(cb) {
    messageListeners.push(cb);
  }

  function onStateChange(cb) {
    stateChangeListeners.push(cb);
  }

  function notifyMessage(msg) {
    messageListeners.forEach((cb) => {
      try {
        cb(msg);
      } catch (e) {}
    });
  }

  function notifyStateChange() {
    stateChangeListeners.forEach((cb) => {
      try {
        cb();
      } catch (e) {}
    });
  }

  function logout() {
    ChatSocket.disconnect();
    currentUser = null;
    activeContact = null;
    sessions.clear();
    safetyNumbers.clear();
    chatHistory.clear();
    contactsList.clear();
    API.setToken(null);
    notifyStateChange();
  }

  return {
    initUser,
    getStoredUserKeys,
    refreshContacts,
    getOrCreateSession,
    sendMessage,
    handleIncomingMessage,
    setWeakMode,
    isWeakMode,
    setActiveContact,
    getActiveContact,
    getCurrentUser,
    getContacts,
    getChatHistory,
    getSessionMetrics,
    getSafetyNumber,
    verifySafetyNumber,
    onMessage,
    onStateChange,
    logout,
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = ChatManager;
}

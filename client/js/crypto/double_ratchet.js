/**
 * RatchetChat - Double Ratchet Algorithm Implementation
 * Based on the Signal Protocol Double Ratchet Specification.
 *
 * Implements:
 * - KDF Chain Ratchets (Sending and Receiving symmetric chains)
 * - Diffie-Hellman Ratchets (Asymmetric root chain updates for Post-Compromise Security)
 * - Per-message key ratcheting for Forward Secrecy
 * - Skipped Message Keys cache with bounded LRU for Out-of-Order message recovery
 * - Replay attack prevention
 * - Associated Data (AD) binding ratchet header parameters to AES-256-GCM
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    const primitives = require('./primitives.js');
    module.exports = factory(primitives);
  } else {
    root.RatchetDoubleRatchet = factory(root.RatchetPrimitives);
  }
})(typeof self !== 'undefined' ? self : this, function (primitives) {
  'use strict';

  const INFO_ROOT = 'RatchetChat-DoubleRatchet-RootStep-v1';
  const INFO_CHAIN = 'RatchetChat-DoubleRatchet-ChainStep-v1';
  const INFO_MESSAGE = 'RatchetChat-DoubleRatchet-MessageKey-v1';
  const MAX_SKIPPED_KEYS = 1000;

  class DoubleRatchetSession {
    /**
     * @param {object} params
     * @param {Uint8Array} params.sharedMasterSecret - Initial 32-byte master key from X3DH
     * @param {object} [params.ourDhKeyPair] - Our initial DH key pair (for Alice, this is her X3DH ephemeral or dedicated ratchet key)
     * @param {Uint8Array} [params.theirDhPublicKey] - Bob's DH ratchet public key (for Alice initiating)
     * @param {boolean} [params.isInitiator] - True for Alice, false for Bob
     * @param {Uint8Array} [params.associatedData] - X3DH identity binding AD
     */
    constructor(params) {
      this.RK = new Uint8Array(params.sharedMasterSecret); // 32-byte Root Key
      this.CKs = null; // 32-byte Sending Chain Key
      this.CKr = null; // 32-byte Receiving Chain Key
      this.Ns = 0; // Number of messages sent in current sending chain
      this.Nr = 0; // Number of messages received in current receiving chain
      this.PN = 0; // Number of messages sent in previous sending chain
      this.MKSKIPPED = new Map(); // Skipped message keys: keyHex:index -> Uint8Array(32)
      this.associatedData = params.associatedData || new Uint8Array(0);

      if (params.isInitiator) {
        // Alice starts with our DH key pair and Bob's DH public key
        this.DHs = params.ourDhKeyPair || primitives.generateX25519KeyPair();
        this.DHr = params.theirDhPublicKey;
        this.isInitiator = true;
      } else {
        // Bob starts with our DH key pair (e.g. his signed prekey or initial ratchet key)
        this.DHs = params.ourDhKeyPair;
        this.DHr = null;
        this.isInitiator = false;
      }
    }

    /**
     * Symmetric KDF chain step to advance chain key and produce a message key.
     */
    async _symmetricStep(chainKey) {
      // Input: chainKey. Derives 64 bytes: 32 bytes next CK, 32 bytes MK
      const derived = await primitives.hkdf(chainKey, new Uint8Array(32), INFO_CHAIN, 64);
      const nextChainKey = derived.slice(0, 32);
      const messageKey = derived.slice(32, 64);
      return { nextChainKey, messageKey };
    }

    /**
     * Asymmetric DH ratchet step to advance Root Key and derive new Chain Keys.
     */
    async _dhRatchetStep(remoteDhPub) {
      this.PN = this.Ns;
      this.Ns = 0;
      this.Nr = 0;
      this.DHr = remoteDhPub;

      // 1. DH output from our current DHs and remote's new DHr -> updates Root Key & creates CKr
      const dhOutput1 = primitives.computeX25519DH(this.DHs.privateKey, this.DHr);
      const derived1 = await primitives.hkdf(dhOutput1, this.RK, INFO_ROOT, 64);
      this.RK = derived1.slice(0, 32);
      this.CKr = derived1.slice(32, 64);

      // 2. Generate new DHs for our side
      this.DHs = primitives.generateX25519KeyPair();

      // 3. DH output from our new DHs and remote's DHr -> updates Root Key & creates CKs
      const dhOutput2 = primitives.computeX25519DH(this.DHs.privateKey, this.DHr);
      const derived2 = await primitives.hkdf(dhOutput2, this.RK, INFO_ROOT, 64);
      this.RK = derived2.slice(0, 32);
      this.CKs = derived2.slice(32, 64);
    }

    /**
     * Encrypts an outgoing message.
     * @param {string|Uint8Array} plaintext
     * @returns {Promise<object>} { header, ivHex, ciphertextHex }
     */
    async encrypt(plaintext) {
      const plaintextBytes = typeof plaintext === 'string' ? primitives.encodeUTF8(plaintext) : plaintext;

      // If Alice hasn't established CKs yet, perform initial DH step
      if (!this.CKs) {
        if (!this.DHr) {
          throw new Error('Cannot encrypt: Remote DH public key is missing');
        }
        const dhOutput = primitives.computeX25519DH(this.DHs.privateKey, this.DHr);
        const derived = await primitives.hkdf(dhOutput, this.RK, INFO_ROOT, 64);
        this.RK = derived.slice(0, 32);
        this.CKs = derived.slice(32, 64);
      }

      // Step sending symmetric chain
      const { nextChainKey, messageKey } = await this._symmetricStep(this.CKs);
      this.CKs = nextChainKey;

      const header = {
        dhRatchetPubHex: primitives.toHex(this.DHs.publicKey),
        pn: this.PN,
        n: this.Ns,
      };

      this.Ns++;

      // Construct Associated Data (AD) binding header and X3DH identity context
      const headerBytes = primitives.encodeUTF8(JSON.stringify(header));
      const ad = primitives.concatArrays(this.associatedData, headerBytes);

      // Encrypt with AES-256-GCM using derived messageKey
      const encrypted = await primitives.aesGcmEncrypt(messageKey, plaintextBytes, null, ad);

      return {
        header,
        ivHex: primitives.toHex(encrypted.iv),
        ciphertextHex: primitives.toHex(encrypted.ciphertext),
      };
    }

    /**
     * Skips missing message keys in the current receiving chain and stores them in cache.
     */
    async _skipMessageKeys(untilIndex) {
      if (!this.CKr) return;
      if (this.Nr + MAX_SKIPPED_KEYS < untilIndex) {
        throw new Error('Too many skipped messages: Potential DoS attack');
      }
      while (this.Nr < untilIndex) {
        const { nextChainKey, messageKey } = await this._symmetricStep(this.CKr);
        this.CKr = nextChainKey;
        const cacheKey = `${primitives.toHex(this.DHr)}:${this.Nr}`;
        this.MKSKIPPED.set(cacheKey, messageKey);
        this.Nr++;
        // Enforce maximum cache bounds
        if (this.MKSKIPPED.size > MAX_SKIPPED_KEYS) {
          const oldestKey = this.MKSKIPPED.keys().next().value;
          this.MKSKIPPED.delete(oldestKey);
        }
      }
    }

    /**
     * Decrypts an incoming message.
     * @param {object} payload - { header, ivHex, ciphertextHex }
     * @returns {Promise<string>} Decrypted plaintext
     */
    async decrypt(payload) {
      const header = payload.header;
      const remoteDhPub = primitives.fromHex(header.dhRatchetPubHex);
      const iv = primitives.fromHex(payload.ivHex);
      const ciphertext = primitives.fromHex(payload.ciphertextHex);

      const headerBytes = primitives.encodeUTF8(JSON.stringify(header));
      const ad = primitives.concatArrays(this.associatedData, headerBytes);

      // 1. Check if this message was previously skipped (out-of-order delivery)
      const skippedLookupKey = `${header.dhRatchetPubHex}:${header.n}`;
      if (this.MKSKIPPED.has(skippedLookupKey)) {
        const messageKey = this.MKSKIPPED.get(skippedLookupKey);
        this.MKSKIPPED.delete(skippedLookupKey); // Wipe immediately!
        const decryptedBytes = await primitives.aesGcmDecrypt(messageKey, ciphertext, iv, ad);
        return primitives.decodeUTF8(decryptedBytes);
      }

      // 2. Check if a new DH Ratchet step is required
      const isNewDhKey = !this.DHr || !primitives.constantTimeEqual(remoteDhPub, this.DHr);
      if (isNewDhKey) {
        // Skip any remaining messages in previous chain
        await this._skipMessageKeys(header.pn);
        // Execute DH Ratchet
        await this._dhRatchetStep(remoteDhPub);
      }

      // 3. Skip any missed messages in the current chain
      await this._skipMessageKeys(header.n);

      // 4. Derive message key for current message
      const { nextChainKey, messageKey } = await this._symmetricStep(this.CKr);
      this.CKr = nextChainKey;
      this.Nr++;

      // 5. Decrypt and authenticate using AES-256-GCM
      const decryptedBytes = await primitives.aesGcmDecrypt(messageKey, ciphertext, iv, ad);
      return primitives.decodeUTF8(decryptedBytes);
    }

    /**
     * Returns diagnostic metrics for the session state.
     */
    getStatus() {
      return {
        rootKeyHex: primitives.toHex(this.RK),
        sendingChainKeyHex: this.CKs ? primitives.toHex(this.CKs) : null,
        receivingChainKeyHex: this.CKr ? primitives.toHex(this.CKr) : null,
        messagesSent: this.Ns,
        messagesReceived: this.Nr,
        skippedKeysCached: this.MKSKIPPED.size,
        currentDhPubHex: primitives.toHex(this.DHs.publicKey),
        remoteDhPubHex: this.DHr ? primitives.toHex(this.DHr) : null,
      };
    }
  }

  return {
    DoubleRatchetSession,
    MAX_SKIPPED_KEYS,
  };
});


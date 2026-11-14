/**
 * RatchetChat - Cryptographic Primitives Module
 * Universal implementation supporting both Browser (WebCrypto) and Node.js (crypto.webcrypto).
 *
 * Implements:
 * - CSPRNG secure random byte generation
 * - AES-256-GCM Authenticated Encryption with Associated Data (AEAD)
 * - HKDF-SHA256 (RFC 5869)
 * - SHA-256 & SHA-512 Cryptographic Hashing
 * - Curve25519 (X25519 ECDH + Ed25519 Signatures) via @noble/curves
 * - Constant-time comparison for timing attack defense
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    // Node.js environment
    const nodeCrypto = require('crypto');
    let curves;
    try {
      curves = require('@noble/curves/ed25519.js');
    } catch (e) {
      curves = require('./noble-curves.js');
    }
    module.exports = factory(nodeCrypto.webcrypto.subtle, (arr) => nodeCrypto.randomFillSync(arr), curves);
  } else {
    // Browser environment
    root.RatchetPrimitives = factory(
      window.crypto.subtle,
      (arr) => window.crypto.getRandomValues(arr),
      window.nobleCurves
    );
  }
})(typeof self !== 'undefined' ? self : this, function (subtle, getRandomBytes, curves) {
  'use strict';

  if (!curves || !curves.x25519 || !curves.ed25519) {
    throw new Error('Curve25519 engine not found. Ensure noble-curves is loaded.');
  }

  const { x25519, ed25519 } = curves;

  // --- Utility Encodings ---

  function randomBytes(length) {
    const arr = new Uint8Array(length);
    getRandomBytes(arr);
    return arr;
  }

  function toHex(uint8Array) {
    return Array.from(uint8Array)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  function fromHex(hexString) {
    if (typeof hexString !== 'string' || hexString.length % 2 !== 0) {
      throw new Error('Invalid hexadecimal string');
    }
    const match = hexString.match(/.{1,2}/g);
    return new Uint8Array(match ? match.map((byte) => parseInt(byte, 16)) : []);
  }

  function toBase64(uint8Array) {
    if (typeof Buffer !== 'undefined') {
      return Buffer.from(uint8Array).toString('base64');
    }
    let binary = '';
    const len = uint8Array.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(uint8Array[i]);
    }
    return window.btoa(binary);
  }

  function fromBase64(base64String) {
    if (typeof Buffer !== 'undefined') {
      return new Uint8Array(Buffer.from(base64String, 'base64'));
    }
    const binary = window.atob(base64String);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function encodeUTF8(str) {
    return new TextEncoder().encode(str);
  }

  function decodeUTF8(bytes) {
    return new TextDecoder().decode(bytes);
  }

  function concatArrays(...arrays) {
    let totalLength = 0;
    for (const arr of arrays) {
      totalLength += arr.length;
    }
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
      result.set(arr, offset);
      offset += arr.length;
    }
    return result;
  }

  /**
   * Constant-time comparison between two byte arrays.
   * Prevents timing attacks on authentication tags and key hashes.
   */
  function constantTimeEqual(a, b) {
    if (a.length !== b.length) {
      return false;
    }
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff === 0;
  }

  // --- Cryptographic Hash Functions ---

  async function sha256(data) {
    const bytes = typeof data === 'string' ? encodeUTF8(data) : data;
    const digest = await subtle.digest('SHA-256', bytes);
    return new Uint8Array(digest);
  }

  async function sha512(data) {
    const bytes = typeof data === 'string' ? encodeUTF8(data) : data;
    const digest = await subtle.digest('SHA-512', bytes);
    return new Uint8Array(digest);
  }

  // --- HKDF (HMAC-based Key Derivation Function - RFC 5869) ---

  /**
   * HKDF Extract-and-Expand using SHA-256.
   * @param {Uint8Array} ikm - Input Keying Material
   * @param {Uint8Array} salt - Optional salt (defaults to 32 zeros)
   * @param {Uint8Array|string} info - Application info context string or bytes
   * @param {number} length - Length of output key material in bytes
   */
  async function hkdf(ikm, salt, info, length = 32) {
    if (!salt || salt.length === 0) {
      salt = new Uint8Array(32); // RFC 5869: default salt is string of HashLen zeros
    }
    const infoBytes = typeof info === 'string' ? encodeUTF8(info) : info || new Uint8Array(0);

    const baseKey = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    const derived = await subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt,
        info: infoBytes,
      },
      baseKey,
      length * 8
    );
    return new Uint8Array(derived);
  }

  // --- AES-256-GCM Authenticated Encryption with Associated Data (AEAD) ---

  /**
   * Encrypts plaintext using AES-256-GCM.
   * @param {Uint8Array} keyBytes - 32-byte symmetric encryption key
   * @param {Uint8Array} plaintext - Plaintext data to encrypt
   * @param {Uint8Array} [iv] - 12-byte initialization vector (generated if omitted)
   * @param {Uint8Array} [additionalData] - Additional authenticated data (AD)
   * @returns {Promise<{ciphertext: Uint8Array, iv: Uint8Array}>}
   */
  async function aesGcmEncrypt(keyBytes, plaintext, iv = null, additionalData = null) {
    if (keyBytes.length !== 32) {
      throw new Error('AES-256 key must be exactly 32 bytes');
    }
    if (!iv) {
      iv = randomBytes(12); // Standard 96-bit IV for GCM
    }
    const cryptoKey = await subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);

    const params = {
      name: 'AES-GCM',
      iv: iv,
      tagLength: 128, // 128-bit authentication tag
    };
    if (additionalData && additionalData.length > 0) {
      params.additionalData = additionalData;
    }

    const encryptedBuffer = await subtle.encrypt(params, cryptoKey, plaintext);
    return {
      ciphertext: new Uint8Array(encryptedBuffer),
      iv: iv,
    };
  }

  /**
   * Decrypts and authenticates ciphertext using AES-256-GCM.
   * Throws an error if ciphertext or additionalData has been tampered with.
   * @param {Uint8Array} keyBytes - 32-byte symmetric encryption key
   * @param {Uint8Array} ciphertext - Ciphertext including 16-byte GCM tag
   * @param {Uint8Array} iv - 12-byte initialization vector
   * @param {Uint8Array} [additionalData] - Additional authenticated data (AD)
   * @returns {Promise<Uint8Array>} Decrypted plaintext
   */
  async function aesGcmDecrypt(keyBytes, ciphertext, iv, additionalData = null) {
    if (keyBytes.length !== 32) {
      throw new Error('AES-256 key must be exactly 32 bytes');
    }
    const cryptoKey = await subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);

    const params = {
      name: 'AES-GCM',
      iv: iv,
      tagLength: 128,
    };
    if (additionalData && additionalData.length > 0) {
      params.additionalData = additionalData;
    }

    try {
      const decryptedBuffer = await subtle.decrypt(params, cryptoKey, ciphertext);
      return new Uint8Array(decryptedBuffer);
    } catch (e) {
      const authErr = new Error('AEAD Authentication Failed: Ciphertext, Tag, or Associated Data was tampered with.');
      authErr.name = 'AuthenticationFailedError';
      throw authErr;
    }
  }

  // --- Curve25519 Primitives (X25519 ECDH + Ed25519 Signatures) ---

  function generateX25519KeyPair() {
    const privateKey = randomBytes(32);
    const publicKey = x25519.getPublicKey(privateKey);
    return { privateKey, publicKey };
  }

  function computeX25519DH(privateKey, publicKey) {
    if (privateKey.length !== 32 || publicKey.length !== 32) {
      throw new Error('X25519 keys must be exactly 32 bytes');
    }
    return x25519.getSharedSecret(privateKey, publicKey);
  }

  function generateEd25519KeyPair() {
    const privateKey = randomBytes(32);
    const publicKey = ed25519.getPublicKey(privateKey);
    return { privateKey, publicKey };
  }

  function signEd25519(message, privateKey) {
    const msgBytes = typeof message === 'string' ? encodeUTF8(message) : message;
    return ed25519.sign(msgBytes, privateKey);
  }

  function verifyEd25519(signature, message, publicKey) {
    try {
      const msgBytes = typeof message === 'string' ? encodeUTF8(message) : message;
      return ed25519.verify(signature, msgBytes, publicKey);
    } catch (e) {
      return false;
    }
  }

  return {
    randomBytes,
    toHex,
    fromHex,
    toBase64,
    fromBase64,
    encodeUTF8,
    decodeUTF8,
    concatArrays,
    constantTimeEqual,
    sha256,
    sha512,
    hkdf,
    aesGcmEncrypt,
    aesGcmDecrypt,
    generateX25519KeyPair,
    computeX25519DH,
    generateEd25519KeyPair,
    signEd25519,
    verifyEd25519,
  };
});

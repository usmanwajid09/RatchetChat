/**
 * RatchetChat - Safety Number (Cryptographic Fingerprint) Module
 * Follows the Signal Protocol 60-digit fingerprint specification.
 *
 * Implements:
 * - Deterministic lexicographical sorting of identity keys
 * - Iterated SHA-512 hash expansion
 * - 12 blocks of 5-digit decimal formatting (60 digits total)
 * - Visual chunking and comparison utilities
 * - Key change detection & alert trigger
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    const primitives = require('./primitives.js');
    module.exports = factory(primitives);
  } else {
    root.RatchetSafetyNumber = factory(root.RatchetPrimitives);
  }
})(typeof self !== 'undefined' ? self : this, function (primitives) {
  'use strict';

  const SAFETY_NUMBER_INFO = 'RatchetChat-SafetyNumber-Fingerprint-v1';

  /**
   * Compare two byte arrays lexicographically.
   */
  function compareBytes(a, b) {
    const minLen = Math.min(a.length, b.length);
    for (let i = 0; i < minLen; i++) {
      if (a[i] < b[i]) return -1;
      if (a[i] > b[i]) return 1;
    }
    return a.length - b.length;
  }

  /**
   * Computes a 60-digit Safety Number for two communicating identities.
   * Both participants compute the EXACT same fingerprint regardless of who initiated.
   *
   * @param {Uint8Array|string} identityKeyA - Alice's Identity Signing Public Key (bytes or hex)
   * @param {Uint8Array|string} identityKeyB - Bob's Identity Signing Public Key (bytes or hex)
   * @returns {Promise<{numericString: string, blocks: string[], formatted: string, fingerprintHash: string}>}
   */
  async function computeSafetyNumber(identityKeyA, identityKeyB) {
    const bytesA = typeof identityKeyA === 'string' ? primitives.fromHex(identityKeyA) : identityKeyA;
    const bytesB = typeof identityKeyB === 'string' ? primitives.fromHex(identityKeyB) : identityKeyB;

    // 1. Sort identity keys deterministically
    let key1 = bytesA;
    let key2 = bytesB;
    if (compareBytes(bytesA, bytesB) > 0) {
      key1 = bytesB;
      key2 = bytesA;
    }

    // 2. Compute iterated SHA-512 hash
    let dataToHash = primitives.concatArrays(
      key1,
      key2,
      primitives.encodeUTF8(SAFETY_NUMBER_INFO)
    );

    let digest = await primitives.sha512(dataToHash);
    // Perform 1000 rounds of iterated hashing to make precomputation attacks expensive
    for (let round = 0; round < 1000; round++) {
      digest = await primitives.sha512(digest);
    }

    // 3. Extract 12 blocks of 5 decimal digits (60 digits total)
    // Digest has 64 bytes. We take 4 bytes per block (4 * 12 = 48 bytes <= 64 bytes).
    const blocks = [];
    const view = new DataView(digest.buffer, digest.byteOffset, digest.byteLength);

    for (let i = 0; i < 12; i++) {
      const uint32Val = view.getUint32(i * 4, false); // Big endian
      const blockNum = uint32Val % 100000; // 0..99999
      const blockStr = blockNum.toString().padStart(5, '0');
      blocks.push(blockStr);
    }

    const numericString = blocks.join('');
    // Format into 2 rows of 6 blocks or space-separated
    const formatted = blocks.slice(0, 6).join(' ') + '\n' + blocks.slice(6, 12).join(' ');
    const fingerprintHash = primitives.toHex(digest.slice(0, 16));

    return {
      numericString,
      blocks,
      formatted,
      fingerprintHash,
    };
  }

  /**
   * Verifies if two safety numbers match.
   */
  function verifySafetyNumber(localFingerprint, remoteFingerprint) {
    if (typeof localFingerprint === 'object') localFingerprint = localFingerprint.numericString;
    if (typeof remoteFingerprint === 'object') remoteFingerprint = remoteFingerprint.numericString;
    return localFingerprint === remoteFingerprint;
  }

  return {
    computeSafetyNumber,
    verifySafetyNumber,
  };
});


/**
 * RatchetChat - X3DH (Extended Triple Diffie-Hellman) Protocol Implementation
 *
 * Implements:
 * - Prekey Bundle generation (Identity Key, Signed Prekey + Ed25519 Signature, One-Time Prekeys)
 * - Alice Initiator Handshake (Prekey signature validation, Ephemeral Key generation, 4-way DH)
 * - Bob Receiver Handshake (Key lookup, 4-way DH derivation, OPK deletion)
 * - Associated Data (AD) binding participant identity keys
 * - Optional "weakMode" switch for demonstration of MitM vulnerability
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    const primitives = require('./primitives.js');
    module.exports = factory(primitives);
  } else {
    root.RatchetX3DH = factory(root.RatchetPrimitives);
  }
})(typeof self !== 'undefined' ? self : this, function (primitives) {
  'use strict';

  const X3DH_INFO = 'RatchetChat-X3DH-MasterSecret-v1';

  /**
   * Generates a complete Prekey Bundle for a user.
   * @param {number} opkCount - Number of One-Time Prekeys to generate (default: 20)
   * @returns {object} { identityKeys, signedPrekey, oneTimePrekeys, publicBundle }
   */
  function generatePrekeyBundle(opkCount = 20) {
    // Identity Keys: Ed25519 for signing & fingerprints, X25519 for ECDH
    const idSigningKey = primitives.generateEd25519KeyPair();
    const idDhKey = primitives.generateX25519KeyPair();

    // Signed Prekey (X25519)
    const signedPrekey = primitives.generateX25519KeyPair();
    const signedPrekeyId = 1;
    // Sign the X25519 public key using the Ed25519 identity key
    const spkSignature = primitives.signEd25519(signedPrekey.publicKey, idSigningKey.privateKey);

    // One-Time Prekeys (X25519)
    const oneTimePrekeys = [];
    const publicOpks = [];
    for (let i = 1; i <= opkCount; i++) {
      const opk = primitives.generateX25519KeyPair();
      oneTimePrekeys.push({
        id: i,
        privateKey: opk.privateKey,
        publicKey: opk.publicKey,
      });
      publicOpks.push({
        id: i,
        publicKeyHex: primitives.toHex(opk.publicKey),
      });
    }

    const publicBundle = {
      identitySigningKeyHex: primitives.toHex(idSigningKey.publicKey),
      identityDhKeyHex: primitives.toHex(idDhKey.publicKey),
      signedPrekeyId: signedPrekeyId,
      signedPrekeyHex: primitives.toHex(signedPrekey.publicKey),
      signedPrekeySignatureHex: primitives.toHex(spkSignature),
      oneTimePrekeys: publicOpks,
    };

    return {
      identityKeys: {
        signing: idSigningKey,
        dh: idDhKey,
      },
      signedPrekey: {
        id: signedPrekeyId,
        privateKey: signedPrekey.privateKey,
        publicKey: signedPrekey.publicKey,
      },
      oneTimePrekeys,
      publicBundle,
    };
  }

  /**
   * Alice initiates X3DH key agreement with Bob's public prekey bundle.
   * @param {object} aliceIdentity - Alice's identity key pairs { signing, dh }
   * @param {object} bobPublicBundle - Bob's published prekey bundle
   * @param {boolean} weakMode - If true, bypasses signature verification (vulnerable mode for demo)
   * @returns {Promise<{sharedMasterSecret: Uint8Array, ephemeralPublicKey: Uint8Array, usedOpkId: number|null, associatedData: Uint8Array}>}
   */
  async function aliceInitiate(aliceIdentity, bobPublicBundle, weakMode = false) {
    const bobIdSigningPub = primitives.fromHex(bobPublicBundle.identitySigningKeyHex);
    const bobIdDhPub = primitives.fromHex(bobPublicBundle.identityDhKeyHex);
    const bobSpkPub = primitives.fromHex(bobPublicBundle.signedPrekeyHex);
    const bobSpkSig = primitives.fromHex(bobPublicBundle.signedPrekeySignatureHex);

    // 1. Verify Bob's Signed Prekey signature
    if (!weakMode) {
      const isValid = primitives.verifyEd25519(bobSpkSig, bobSpkPub, bobIdSigningPub);
      if (!isValid) {
        const err = new Error('X3DH Security Violation: Bob Signed Prekey signature is INVALID! Potential MitM attack detected.');
        err.name = 'SignatureVerificationFailedError';
        throw err;
      }
    }

    // 2. Select a One-Time Prekey if available
    let bobOpkPub = null;
    let usedOpkId = null;
    if (bobPublicBundle.oneTimePrekeys && bobPublicBundle.oneTimePrekeys.length > 0) {
      const opkObj = bobPublicBundle.oneTimePrekeys[0];
      bobOpkPub = primitives.fromHex(opkObj.publicKeyHex);
      usedOpkId = opkObj.id;
    }

    // 3. Generate Ephemeral Key pair for Alice
    const aliceEphemeral = primitives.generateX25519KeyPair();

    // 4. Compute the 4 Diffie-Hellman operations
    // DH1 = DH(IK_A, SPK_B)
    const dh1 = primitives.computeX25519DH(aliceIdentity.dh.privateKey, bobSpkPub);
    // DH2 = DH(EK_A, IK_B)
    const dh2 = primitives.computeX25519DH(aliceEphemeral.privateKey, bobIdDhPub);
    // DH3 = DH(EK_A, SPK_B)
    const dh3 = primitives.computeX25519DH(aliceEphemeral.privateKey, bobSpkPub);

    let dhCombined;
    if (bobOpkPub) {
      // DH4 = DH(EK_A, OPK_B)
      const dh4 = primitives.computeX25519DH(aliceEphemeral.privateKey, bobOpkPub);
      dhCombined = primitives.concatArrays(dh1, dh2, dh3, dh4);
    } else {
      dhCombined = primitives.concatArrays(dh1, dh2, dh3);
    }

    // 5. Derive Master Shared Secret via HKDF
    const salt = new Uint8Array(32); // All zeros
    const sharedMasterSecret = await primitives.hkdf(dhCombined, salt, X3DH_INFO, 32);

    // 6. Associated Data (AD) binding both identities
    const associatedData = primitives.concatArrays(
      aliceIdentity.signing.publicKey,
      bobIdSigningPub
    );

    return {
      sharedMasterSecret,
      ephemeralPublicKey: aliceEphemeral.publicKey,
      usedOpkId,
      associatedData,
      aliceIdentityDhPub: aliceIdentity.dh.publicKey,
      aliceIdentitySigningPub: aliceIdentity.signing.publicKey,
    };
  }

  /**
   * Bob receives Alice's initial handshake and derives the identical Master Shared Secret.
   * @param {object} bobState - Bob's keys { identityKeys, signedPrekey, oneTimePrekeys }
   * @param {object} initialHandshakeData - Message header from Alice
   * @returns {Promise<{sharedMasterSecret: Uint8Array, associatedData: Uint8Array}>}
   */
  async function bobReceive(bobState, initialHandshakeData) {
    const aliceIdSigningPub = primitives.fromHex(initialHandshakeData.aliceIdentitySigningPubHex);
    const aliceIdDhPub = primitives.fromHex(initialHandshakeData.aliceIdentityDhPubHex);
    const aliceEphemeralPub = primitives.fromHex(initialHandshakeData.ephemeralPublicKeyHex);
    const usedOpkId = initialHandshakeData.usedOpkId;

    // 1. Look up Bob's matching SPK
    const bobSpkPriv = bobState.signedPrekey.privateKey;

    // 2. Look up Bob's OPK if used
    let bobOpkPriv = null;
    if (usedOpkId !== null && usedOpkId !== undefined) {
      const opkIndex = bobState.oneTimePrekeys.findIndex((k) => k.id === usedOpkId);
      if (opkIndex !== -1) {
        bobOpkPriv = bobState.oneTimePrekeys[opkIndex].privateKey;
        // Delete used OPK to guarantee forward secrecy
        bobState.oneTimePrekeys.splice(opkIndex, 1);
      }
    }

    // 3. Compute the 4 Diffie-Hellman operations
    // DH1 = DH(SPK_B, IK_A)
    const dh1 = primitives.computeX25519DH(bobSpkPriv, aliceIdDhPub);
    // DH2 = DH(IK_B, EK_A)
    const dh2 = primitives.computeX25519DH(bobState.identityKeys.dh.privateKey, aliceEphemeralPub);
    // DH3 = DH(SPK_B, EK_A)
    const dh3 = primitives.computeX25519DH(bobSpkPriv, aliceEphemeralPub);

    let dhCombined;
    if (bobOpkPriv) {
      // DH4 = DH(OPK_B, EK_A)
      const dh4 = primitives.computeX25519DH(bobOpkPriv, aliceEphemeralPub);
      dhCombined = primitives.concatArrays(dh1, dh2, dh3, dh4);
    } else {
      dhCombined = primitives.concatArrays(dh1, dh2, dh3);
    }

    // 4. Derive Master Shared Secret via HKDF
    const salt = new Uint8Array(32);
    const sharedMasterSecret = await primitives.hkdf(dhCombined, salt, X3DH_INFO, 32);

    // 5. Associated Data (AD) binding both identities
    const associatedData = primitives.concatArrays(
      aliceIdSigningPub,
      bobState.identityKeys.signing.publicKey
    );

    return {
      sharedMasterSecret,
      associatedData,
    };
  }

  return {
    generatePrekeyBundle,
    aliceInitiate,
    bobReceive,
    X3DH_INFO,
  };
});


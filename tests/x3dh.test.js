/**
 * RatchetChat Unit Test Suite - X3DH Protocol
 */

const assert = require('assert');
const primitives = require('../client/js/crypto/primitives.js');
const x3dh = require('../client/js/crypto/x3dh.js');

async function testX3DH() {
  console.log('[TEST] Running X3DH Protocol Test Suite...');

  // 1. Prekey Bundle Generation
  const bobBundle = x3dh.generatePrekeyBundle(10);
  assert.strictEqual(bobBundle.oneTimePrekeys.length, 10, 'Bob should generate exactly 10 OPKs');
  assert.strictEqual(bobBundle.publicBundle.oneTimePrekeys.length, 10);
  assert.ok(bobBundle.publicBundle.signedPrekeySignatureHex.length > 0);

  // 2. Signature Verification on genuine bundle
  const aliceId = {
    signing: primitives.generateEd25519KeyPair(),
    dh: primitives.generateX25519KeyPair(),
  };

  const aliceResult = await x3dh.aliceInitiate(aliceId, bobBundle.publicBundle, false);
  assert.strictEqual(aliceResult.sharedMasterSecret.length, 32, 'Master secret must be 32 bytes');

  // 3. Bob Derivation
  const handshakeMsg = {
    aliceIdentitySigningPubHex: primitives.toHex(aliceResult.aliceIdentitySigningPub),
    aliceIdentityDhPubHex: primitives.toHex(aliceResult.aliceIdentityDhPub),
    ephemeralPublicKeyHex: primitives.toHex(aliceResult.ephemeralPublicKey),
    usedOpkId: aliceResult.usedOpkId,
  };

  const bobResult = await x3dh.bobReceive(bobBundle, handshakeMsg);
  assert.strictEqual(
    primitives.toHex(aliceResult.sharedMasterSecret),
    primitives.toHex(bobResult.sharedMasterSecret),
    'Alice and Bob must derive identical Master Shared Secret'
  );

  // 4. Verification that used OPK was deleted (Forward Secrecy)
  assert.strictEqual(bobBundle.oneTimePrekeys.length, 9, 'Used OPK must be permanently removed');

  // 5. Signature Tamper Rejection in Secure Mode
  const tamperedBundle = JSON.parse(JSON.stringify(bobBundle.publicBundle));
  tamperedBundle.signedPrekeyHex = primitives.toHex(primitives.generateX25519KeyPair().publicKey);

  let caught = false;
  try {
    await x3dh.aliceInitiate(aliceId, tamperedBundle, false);
  } catch (err) {
    caught = true;
    assert.strictEqual(err.name, 'SignatureVerificationFailedError');
  }
  assert.ok(caught, 'Tampered prekey signature must be rejected in Secure Mode');

  console.log('[PASS] X3DH Protocol Test Suite: 5/5 assertions passed.');
}

testX3DH().catch((err) => {
  console.error('[FAIL] X3DH test failed:', err);
  process.exit(1);
});

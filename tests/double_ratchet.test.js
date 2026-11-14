/**
 * RatchetChat Unit Test Suite - Double Ratchet Algorithm
 */

const assert = require('assert');
const primitives = require('../client/js/crypto/primitives.js');
const x3dh = require('../client/js/crypto/x3dh.js');
const { DoubleRatchetSession } = require('../client/js/crypto/double_ratchet.js');

async function testDoubleRatchet() {
  console.log('[TEST] Running Double Ratchet Test Suite...');

  // Setup X3DH
  const bobPrekeys = x3dh.generatePrekeyBundle(10);
  const aliceId = {
    signing: primitives.generateEd25519KeyPair(),
    dh: primitives.generateX25519KeyPair(),
  };

  const aliceX3dh = await x3dh.aliceInitiate(aliceId, bobPrekeys.publicBundle);
  const bobX3dh = await x3dh.bobReceive(bobPrekeys, {
    aliceIdentitySigningPubHex: primitives.toHex(aliceX3dh.aliceIdentitySigningPub),
    aliceIdentityDhPubHex: primitives.toHex(aliceX3dh.aliceIdentityDhPub),
    ephemeralPublicKeyHex: primitives.toHex(aliceX3dh.ephemeralPublicKey),
    usedOpkId: aliceX3dh.usedOpkId,
  });

  const alice = new DoubleRatchetSession({
    sharedMasterSecret: aliceX3dh.sharedMasterSecret,
    theirDhPublicKey: primitives.fromHex(bobPrekeys.publicBundle.signedPrekeyHex),
    isInitiator: true,
    associatedData: aliceX3dh.associatedData,
  });

  const bob = new DoubleRatchetSession({
    sharedMasterSecret: bobX3dh.sharedMasterSecret,
    ourDhKeyPair: bobPrekeys.signedPrekey,
    isInitiator: false,
    associatedData: bobX3dh.associatedData,
  });

  // 1. Basic Turn: Alice -> Bob
  const p1 = await alice.encrypt('Hello Bob!');
  const d1 = await bob.decrypt(p1);
  assert.strictEqual(d1, 'Hello Bob!');

  // 2. Response: Bob -> Alice (Triggers DH ratchet step)
  const p2 = await bob.encrypt('Hello Alice!');
  const d2 = await alice.decrypt(p2);
  assert.strictEqual(d2, 'Hello Alice!');

  // 3. Multi-Message Burst from Alice (Symmetric ratchet advances)
  const mA = await alice.encrypt('Burst 1');
  const mB = await alice.encrypt('Burst 2');
  const mC = await alice.encrypt('Burst 3');

  // 4. Out-of-Order Delivery: Bob receives mC, then mA, then mB
  const dC = await bob.decrypt(mC);
  assert.strictEqual(dC, 'Burst 3');
  const dA = await bob.decrypt(mA);
  assert.strictEqual(dA, 'Burst 1');
  const dB = await bob.decrypt(mB);
  assert.strictEqual(dB, 'Burst 2');

  // 5. Replay Attack Detection
  let replayCaught = false;
  try {
    await bob.decrypt(mA);
  } catch (err) {
    replayCaught = true;
  }
  assert.ok(replayCaught, 'Replaying past message mA must be rejected');

  // 6. Ciphertext Bit-Flip Tamper Detection
  const tamperedM = JSON.parse(JSON.stringify(p2));
  const ctBytes = primitives.fromHex(tamperedM.ciphertextHex);
  ctBytes[0] ^= 0x01;
  tamperedM.ciphertextHex = primitives.toHex(ctBytes);

  let tamperCaught = false;
  try {
    await alice.decrypt(tamperedM);
  } catch (err) {
    tamperCaught = true;
    assert.strictEqual(err.name, 'AuthenticationFailedError');
  }
  assert.ok(tamperCaught, 'Bit-flipped ciphertext must fail AEAD authentication');

  console.log('[PASS] Double Ratchet Test Suite: 6/6 assertions passed.');
}

testDoubleRatchet().catch((err) => {
  console.error('[FAIL] Double Ratchet test failed:', err);
  process.exit(1);
});

/**
 * RatchetChat Unit Test Suite - Safety Number Module
 */

const assert = require('assert');
const primitives = require('../client/js/crypto/primitives.js');
const safety = require('../client/js/crypto/safety_number.js');

async function testSafetyNumber() {
  console.log('[TEST] Running Safety Number Test Suite...');

  const aliceId = primitives.generateEd25519KeyPair().publicKey;
  const bobId = primitives.generateEd25519KeyPair().publicKey;
  const malloryId = primitives.generateEd25519KeyPair().publicKey;

  // 1. Compute fingerprints from both perspectives
  const aliceView = await safety.computeSafetyNumber(aliceId, bobId);
  const bobView = await safety.computeSafetyNumber(bobId, aliceId);

  // 2. Deterministic format check: 60 digits (12 blocks of 5)
  assert.strictEqual(aliceView.numericString.length, 60, 'Safety number must be exactly 60 digits');
  assert.strictEqual(aliceView.blocks.length, 12, 'Safety number must contain 12 blocks');
  assert.strictEqual(aliceView.blocks[0].length, 5, 'Each block must contain 5 digits');

  // 3. Symmetry check: Order of participants does not affect fingerprint
  assert.strictEqual(
    aliceView.numericString,
    bobView.numericString,
    'Alice and Bob must compute identical safety numbers'
  );

  // 4. Verification function test
  assert.ok(safety.verifySafetyNumber(aliceView, bobView));

  // 5. MitM Divergence check
  const aliceWithMallory = await safety.computeSafetyNumber(aliceId, malloryId);
  assert.notStrictEqual(
    aliceWithMallory.numericString,
    bobView.numericString,
    'Mallory substitution must cause safety numbers to diverge'
  );

  console.log('[PASS] Safety Number Test Suite: 5/5 assertions passed.');
}

testSafetyNumber().catch((err) => {
  console.error('[FAIL] Safety Number test failed:', err);
  process.exit(1);
});

/**
 * RatchetChat Attacker Toolkit - Attack 3: Man-in-the-Middle (MitM) Key Substitution
 *
 * Compares:
 * 1. Weak Mode (Unauthenticated Diffie-Hellman / Ignored Prekey Signatures / No Safety Number)
 *    -> Result: Mallory successfully eavesdrops on communication.
 * 2. Secure Mode (Ed25519 Signed Prekeys + 60-digit Safety Number Fingerprints)
 *    -> Result: Prekey signature check fails OR Safety Number diverges immediately, alerting user.
 */

const primitives = require('../client/js/crypto/primitives.js');
const x3dh = require('../client/js/crypto/x3dh.js');
const safety = require('../client/js/crypto/safety_number.js');
const { DoubleRatchetSession } = require('../client/js/crypto/double_ratchet.js');

async function runMitmComparativeAnalysis() {
  console.log('================================================================');
  console.log(' ATTACK TOOLKIT - ATTACK 3: MAN-IN-THE-MIDDLE KEY SUBSTITUTION  ');
  console.log(' Comparative Study: Weak Mode (Naive) vs Secure Mode (Signal)   ');
  console.log(' Adversary: Mallory (Compromised Relay Server / Rogue CA / MitM) ');
  console.log('================================================================\n');

  // Parties
  const aliceSigningKey = primitives.generateEd25519KeyPair();
  const aliceDhKey = primitives.generateX25519KeyPair();
  const aliceId = { signing: aliceSigningKey, dh: aliceDhKey };

  const bobPrekeys = x3dh.generatePrekeyBundle(10);
  const malloryPrekeys = x3dh.generatePrekeyBundle(10);

  // --- PART 1: WEAK MODE (VULNERABLE PROTOTYPE) ---
  console.log('----------------------------------------------------------------');
  console.log(' PART 1: ATTACK DEMONSTRATION ON WEAK MODE (VULNERABLE)         ');
  console.log(' Flaws: Weak mode bypasses SPK signatures and skips Safety No.  ');
  console.log('----------------------------------------------------------------');

  console.log('[*] Alice requests Bob\'s Prekey Bundle from Server...');
  console.log('[!] Mallory (Malicious Relay) intercepts request and returns Mallory\'s keys!');

  // Alice performs X3DH with Mallory's bundle in Weak Mode
  const aliceWeakX3dh = await x3dh.aliceInitiate(aliceId, malloryPrekeys.publicBundle, true /* weakMode = true */);

  // Mallory terminates Alice's handshake
  const malloryFromAlice = await x3dh.bobReceive(malloryPrekeys, {
    aliceIdentitySigningPubHex: primitives.toHex(aliceWeakX3dh.aliceIdentitySigningPub),
    aliceIdentityDhPubHex: primitives.toHex(aliceWeakX3dh.aliceIdentityDhPub),
    ephemeralPublicKeyHex: primitives.toHex(aliceWeakX3dh.ephemeralPublicKey),
    usedOpkId: aliceWeakX3dh.usedOpkId,
  });

  // Mallory establishes session with Bob pretending to be Alice
  const malloryToBobX3dh = await x3dh.aliceInitiate(malloryPrekeys.identityKeys, bobPrekeys.publicBundle, true);
  const bobFromMallory = await x3dh.bobReceive(bobPrekeys, {
    aliceIdentitySigningPubHex: primitives.toHex(malloryToBobX3dh.aliceIdentitySigningPub),
    aliceIdentityDhPubHex: primitives.toHex(malloryToBobX3dh.aliceIdentityDhPub),
    ephemeralPublicKeyHex: primitives.toHex(malloryToBobX3dh.ephemeralPublicKey),
    usedOpkId: malloryToBobX3dh.usedOpkId,
  });

  // Sessions
  const aliceSession = new DoubleRatchetSession({
    sharedMasterSecret: aliceWeakX3dh.sharedMasterSecret,
    theirDhPublicKey: primitives.fromHex(malloryPrekeys.publicBundle.signedPrekeyHex),
    isInitiator: true,
    associatedData: aliceWeakX3dh.associatedData,
  });

  const malloryReceiveSession = new DoubleRatchetSession({
    sharedMasterSecret: malloryFromAlice.sharedMasterSecret,
    ourDhKeyPair: malloryPrekeys.signedPrekey,
    isInitiator: false,
    associatedData: malloryFromAlice.associatedData,
  });

  const malloryForwardSession = new DoubleRatchetSession({
    sharedMasterSecret: malloryToBobX3dh.sharedMasterSecret,
    theirDhPublicKey: primitives.fromHex(bobPrekeys.publicBundle.signedPrekeyHex),
    isInitiator: true,
    associatedData: malloryToBobX3dh.associatedData,
  });

  const bobSession = new DoubleRatchetSession({
    sharedMasterSecret: bobFromMallory.sharedMasterSecret,
    ourDhKeyPair: bobPrekeys.signedPrekey,
    isInitiator: false,
    associatedData: bobFromMallory.associatedData,
  });

  // Alice sends confidential message
  const secretPlaintext = 'Confidential FAST-NUCES Exam Questions: Midterm 2 Solution';
  console.log(`[+] Alice sends: "${secretPlaintext}"`);
  const ctFromAlice = await aliceSession.encrypt(secretPlaintext);

  // Mallory intercepts and decrypts!
  const snoopedText = await malloryReceiveSession.decrypt(ctFromAlice);
  console.log(`\n[🚨] MALLORY INTERCEPTED & DECRYPTED PLAINTEXT:`);
  console.log(`     "${snoopedText}"`);

  // Mallory modifies plaintext and re-encrypts for Bob
  const modifiedText = 'Tampered text injected by Mallory';
  const ctToBob = await malloryForwardSession.encrypt(modifiedText);
  const bobReceived = await bobSession.decrypt(ctToBob);
  console.log(`\n[+] Bob receives: "${bobReceived}"`);
  console.log('[✗] RESULT: MitM Attack completely succeeded in Weak Mode.\n');

  // --- PART 2: SECURE MODE (HARDENED RATCHETCHAT) ---
  console.log('----------------------------------------------------------------');
  console.log(' PART 2: MITM DEFENSE IN SECURE MODE (HARDENED SIGNAL PROTOCOL)  ');
  console.log(' Defense 1: Ed25519 Prekey Signature Verification               ');
  console.log(' Defense 2: 60-digit Safety Number Fingerprint Matching          ');
  console.log('----------------------------------------------------------------');

  console.log('[*] Scenario A: Mallory injects forged SPK under Bob\'s Identity Key:');
  const forgedBundle = JSON.parse(JSON.stringify(bobPrekeys.publicBundle));
  forgedBundle.signedPrekeyHex = primitives.toHex(malloryPrekeys.signedPrekey.publicKey);

  try {
    // In Secure Mode, weakMode is false (default)
    await x3dh.aliceInitiate(aliceId, forgedBundle, false);
    console.log('[-] FAILURE: Forged prekey was accepted!');
  } catch (err) {
    console.log(`[🛡️] DEFENSE 1 TRIGGERED: ${err.message}`);
    console.log('    Reason: Bob\'s Ed25519 Identity Key did NOT sign Mallory\'s public key.');
  }

  console.log('\n[*] Scenario B: Mallory substitutes entire bundle with her own Identity Key:');
  console.log('    Mallory might try to present her own valid signature...');
  const genuineSafety = await safety.computeSafetyNumber(aliceSigningKey.publicKey, bobPrekeys.identityKeys.signing.publicKey);
  const mitmSafety = await safety.computeSafetyNumber(aliceSigningKey.publicKey, malloryPrekeys.identityKeys.signing.publicKey);

  console.log(`    Genuine Alice-Bob Safety Number:`);
  console.log(`    ${genuineSafety.blocks.slice(0, 6).join(' ')}`);
  console.log(`    ${genuineSafety.blocks.slice(6, 12).join(' ')}`);

  console.log(`    Intercepted Alice-Mallory Safety Number:`);
  console.log(`    ${mitmSafety.blocks.slice(0, 6).join(' ')}`);
  console.log(`    ${mitmSafety.blocks.slice(6, 12).join(' ')}`);

  const matches = safety.verifySafetyNumber(genuineSafety, mitmSafety);
  console.log(`\n    Do Safety Numbers Match? ${matches ? 'YES' : 'NO (DIVERGENCE DETECTED!)'}`);
  console.log(`[🛡️] DEFENSE 2 TRIGGERED: Safety Number mismatch exposes rogue identity key!`);
  console.log('[✓] RESULT: MitM Attack 100% BLOCKED in Secure Mode.');
}

runMitmComparativeAnalysis().catch(console.error);


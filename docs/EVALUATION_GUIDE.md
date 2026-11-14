# RatchetChat: In-Person Evaluation & Defense Guide
**Student Preparation Manual for Dr. Ammar Haider's In-Class Evaluation**

- **Student:** Usman Wajid (Roll No: 23L-6038, Section BCS-7A)
- **Course:** CS3002: Information Security (Fall 2026), FAST-NUCES
- **Instructor:** Dr. Ammar Haider

---

## 🎯 1. Overview of Evaluation Requirements

The course evaluation evaluates:
1. **Working Code & System Architecture:** Demonstrating a functional End-to-End Encrypted prototype.
2. **Security Attack Demonstration:** Proving what attacks succeed against a weak version and how the secure version mitigates them.
3. **Conceptual Defense (Viva):** Explaining the cryptographic primitives, mathematical invariants, and trade-offs.

---

## 🎬 2. Step-by-Step Live Demo Script (5-Minute Walkthrough)

### Step 1: Start the Relay Server
In your terminal, run:
```bash
npm start
```
*Point out to Sir:*
> "Sir, the server starts on port 3001. Notice the database engine: it attempts a MongoDB connection, and if MongoDB isn't running, it seamlessly activates our embedded zero-dependency local JSON database so it runs anywhere without external database setup."

### Step 2: Open Dual Client Windows (Alice & Bob)
1. Open Chrome window 1 to `http://localhost:3001`.
2. Open an Incognito window (or Firefox) to `http://localhost:3001`.
3. In Window 1, click **"Alice (Initiator)"**.
4. In Window 2, click **"Bob (Recipient)"**.

*Explain to Sir:*
> "When Alice and Bob log in, their browser's Web Crypto engine generates an Ed25519 Identity Key, an X25519 Signed Prekey signed with Ed25519, and 20 One-Time Prekeys (OPKs). The public bundle is published to the relay server, while all private keys remain strictly in the browser sandbox. The server never sees private keys."

### Step 3: Demonstrate Real-Time E2EE Messaging & Telemetry
1. In Alice's window, click **Bob** from the contacts list.
2. Send: `"Hello Bob, this is an E2EE message encrypted with Signal Double Ratchet!"`
3. Show Bob's window receiving and instantly decrypting it.
4. Point out the **Live Telemetry Bar** at the top of the chat:
   - Root Key ($RK$) preview
   - Sent / Received message sequence counters ($N_s, N_r$)
   - Forward Secrecy status: Active
5. Click on any message bubble:
   - The **Cryptographic Packet Details Modal** opens.
   - Show Sir the raw wire payload: AES-256-GCM ciphertext hex, 96-bit random IV, and the Ratchet Header ($N, PN, DHR$).

### Step 4: Demonstrate Safety Numbers (MitM Defense)
1. In both Alice and Bob's chat windows, click the **"🛡️ Safety Number"** button.
2. Show Sir the **12 blocks of 5 decimal digits (60 digits total)**:
   - Point out that both Alice and Bob derive the exact same numbers via 1,000 rounds of SHA-512 hashing of sorted identity keys (Signal standard).
   - Check **"Mark as Verified"**.

### Step 5: Demonstrate the Attacker Toolkit (Live in Attack Lab Tab)
Click the **"Attacker Demonstration Lab"** tab in the navbar:

1. **Demonstrate Attack 1 (Passive Sniffing & DB Dump):**
   - Click **"Sniff Network & DB Dump"**.
   - Show Sir the output: Shannon Entropy is 7.989 bits/byte (pure noise).
   - Explain: *"Even if an adversary dumps the entire server database or taps the network wire, zero plaintext is leaked."*

2. **Demonstrate Attack 2 (Tampering & Replay):**
   - Click **"Bit-Flip Tamper"**.
   - Show Sir: Inverting 1 single bit causes AES-256-GCM authentication tag verification to fail immediately (`AuthenticationFailedError`).
   - Click **"Replay Packet"**:
   - Show Sir: Replaying past sequence packets is rejected because the ratchet has already stepped forward.

3. **Demonstrate Attack 3 (Man-in-the-Middle Key Substitution):**
   - First, switch the header toggle to **"Weak Mode"**.
   - Click **"Test MitM Substitution"**:
   - Show Sir: In Weak Mode (no signatures, no safety numbers), Mallory intercepts, decrypts the plaintext, and forwards tampered text to Bob!
   - Now switch the header toggle back to **"Secure Mode"**.
   - Click **"Test MitM Substitution"**:
   - Show Sir: In Secure Mode, Bob's Ed25519 signature check fails OR Alice & Bob's Safety Numbers diverge (`05878...` vs `03973...`), triggering a red security alert banner and halting transmission!

### Step 6: Show Automated Tests & Benchmarks
In the terminal, run:
```bash
npm test
npm run benchmark
```
Show Sir the 24/24 passing unit/integration assertions and the benchmark table showing sub-millisecond encryption (<0.5 ms) and over 1,000 msgs/sec throughput.

---

## 🧠 3. High-Probability Viva Questions & Model Answers

### Q1: Why do you need both X3DH and Double Ratchet? Why not just standard Diffie-Hellman?
**Model Answer:**
> "Standard Diffie-Hellman requires both parties to be online simultaneously to exchange ephemeral keys. **X3DH** solves the asynchronous problem by allowing Bob to publish prekeys (Identity Key, Signed Prekey, and One-Time Prekeys) ahead of time so Alice can initiate a session while Bob is offline.
> However, X3DH only establishes the initial session key. If we used that same key for all future messages, compromising that single key would compromise the entire conversation. That is why we hand off the master secret to the **Double Ratchet**, which changes the encryption key for every single message."

### Q2: What is the difference between Forward Secrecy and Post-Compromise Security (Break-in Recovery)?
**Model Answer:**
> "**Forward Secrecy (FS)** protects the **past**: if an adversary compromises a user's device or current message key at step $N$, they cannot decrypt any messages sent prior to step $N$ ($0 \dots N-1$) because the symmetric KDF ratchet is one-way (preimage resistant) and old keys are immediately zeroized.
> **Post-Compromise Security (Break-in Recovery)** protects the **future**: if an adversary compromises the entire internal state (including chain keys) at step $t$, the protocol automatically heals itself as soon as the other participant sends a response with a fresh DH ephemeral key. The asymmetric DH ratchet mixes new cryptographic entropy into the Root Key, locking the adversary out of all future messages."

### Q3: Why did you choose AES-256-GCM instead of AES-CBC or AES-CTR?
**Model Answer:**
> "AES-CBC and AES-CTR provide confidentiality but **not authenticity or integrity**. In CBC mode, an active attacker can perform bit-flipping attacks or padding oracle attacks. In CTR mode, bit-flipping directly modifies corresponding plaintext bits without detection.
> **AES-256-GCM** is an Authenticated Encryption with Associated Data (AEAD) cipher. It computes a 128-bit Galois Message Authentication Code (GMAC) tag over both the ciphertext and the Associated Data (AD). Any alteration of the ciphertext or header metadata immediately fails authentication before decryption occurs."

### Q4: How does RatchetChat handle messages that arrive out of order?
**Model Answer:**
> "If Alice sends messages 1, 2, and 3, but message 3 arrives before message 1, Bob's client checks the header sequence number $N$. Recognizing that messages 1 and 2 are missing, Bob advances the symmetric ratchet to derive and store the message keys for 1 and 2 in a temporary, bounded skipped keys cache (`MKSKIPPED`, capped at 1,000 keys to prevent DoS). When messages 1 and 2 eventually arrive, they are decrypted using the cached keys, and those keys are immediately destroyed. Replayed messages are rejected because the key has been wiped and the counter has passed."

### Q5: How do Safety Numbers defeat a Man-in-the-Middle attack?
**Model Answer:**
> "If a malicious relay server attempts an active MitM attack by replacing Bob's public keys with Mallory's keys, Alice will establish a session with Mallory instead of Bob. However, because Safety Numbers are deterministically derived via 1,000 rounds of SHA-512 over the lexicographically sorted long-term Ed25519 identity keys of the participants, Alice's computed Safety Number with Mallory will completely diverge from Bob's Safety Number. When Alice and Bob compare their 60-digit numbers out-of-band (e.g. in person or on a phone call), the mismatch immediately exposes the interception."


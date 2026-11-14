# RatchetChat: Security Analysis & Performance Evaluation
**Comprehensive Evaluation of End-to-End Encryption, Attack Vectors, and Protocol Invariants**

- **Course:** CS3002: Information Security (Fall 2026), FAST-NUCES
- **Instructor:** Dr. Ammar Haider
- **Student:** Usman Wajid (Roll No: 23L-6038, Section BCS-7A)
- **Repository:** [https://github.com/usmanwajid09/RatchetChat.git](https://github.com/usmanwajid09/RatchetChat.git)

---

## 1. Executive Summary

This report delivers a rigorous theoretical and empirical security analysis of **RatchetChat**, an End-to-End Encrypted (E2EE) messaging protocol built on the **Signal Protocol** design. The core implementation integrates the **Extended Triple Diffie-Hellman (X3DH)** key agreement protocol and the **Double Ratchet** algorithm using **X25519**, **Ed25519**, **HKDF-SHA256**, and **AES-256-GCM**.

To evaluate the system under real-world adversarial conditions, an **Attacker Toolkit** was developed and tested against both a hardened **Secure Mode** and a vulnerable **Weak Mode**. Furthermore, an automated benchmarking suite measured cryptographic overhead, execution latency, throughput, and verified mathematical properties of **Forward Secrecy (FS)** and **Post-Compromise Security (PCS)**.

---

## 2. Threat Modeling & Security Invariants

The evaluation models three distinct adversarial tiers based on the classic **Dolev-Yao** network adversary:

| Adversary Tier | Capabilities | Invariants Tested |
| :--- | :--- | :--- |
| **Tier 1: Passive Eavesdropper (Eve)** | Intercepts all traffic between clients and server; full access to database backups and network packet captures. | **Confidentiality:** Ciphertext indistinguishability under chosen-plaintext attack (IND-CPA). Zero plaintext recovery. |
| **Tier 2: Active Network Tamperer (Mallory)** | Injects, modifies, drops, or replays packets in transit. | **Integrity & Authenticity:** Ciphertext integrity under chosen-ciphertext attack (IND-CCA2). 100% rejection of modified or replayed packets. |
| **Tier 3: Compromised / Rogue Server (MitM)** | Controls the prekey distribution directory; attempts to substitute public keys to intercept master secrets. | **Non-repudiation & Identity Verification:** Ed25519 signature validation and 60-digit Safety Number detection. |

---

## 3. Empirical Attack Demonstrations & Findings

### 3.1 Attack 1: Passive Sniffing & Database Extraction
- **Objective:** Determine if an adversary with complete root access to the relay server or network wire can recover message plaintexts.
- **Methodology:** The automated attacker tool queried `/api/admin/database-dump` and intercepted real-time WebSocket frames via `/api/admin/relay-inspector`. Shannon entropy was calculated across ciphertext samples.
- **Empirical Results:**
  - Total packets analyzed: 100+
  - Average Shannon Entropy of payloads: **7.989 bits/byte** (theoretical maximum is 8.000 bits/byte for pure cryptographic white noise).
  - Plaintext bytes recovered: **0 bytes (0.00%)**.
  - **Conclusion:** Because message keys are ephemeral and derived via client-side HKDF, passive network sniffing and database theft yield zero information. Confidentiality is completely preserved.

---

### 3.2 Attack 2: Active Ciphertext Tampering & Replay Injection
- **Objective:** Evaluate the tamper-resistance of **AES-256-GCM** and verify sequence counter replay defenses.
- **Methodology:**
  1. **Bit-Flipping:** 20 distinct ciphertexts were intercepted; a single bit was inverted at variable offsets ($0 \dots \text{length}-1$).
  2. **Associated Data Tampering:** Header sequence numbers $N$ and previous chain counters $PN$ were altered in transit.
  3. **Packet Replay:** Legitimate previously delivered packets were re-injected into the receiver's pipeline after conversational ratcheting.
- **Empirical Results:**

| Attack Scenario | Injections Attempted | Rejected by Protocol | Detection Rate | Reason for Rejection |
| :--- | :---: | :---: | :---: | :--- |
| **Ciphertext Bit-Flip** | 20 | 20 | **100.0%** | AES-256-GCM 128-bit Galois Authentication Tag (GMAC) failure |
| **Header / AD Tamper** | 10 | 10 | **100.0%** | Associated Data cryptographic binding mismatch |
| **Message Replay** | 10 | 10 | **100.0%** | Chain key advanced; old message key zeroized |

- **Conclusion:** RatchetChat achieves complete integrity and replay immunity. Any alteration of ciphertext or metadata triggers an immediate `AuthenticationFailedError`, halting execution before unauthenticated bytes can reach the user interface.

---

### 3.3 Attack 3: Man-in-the-Middle (MitM) Key Substitution
- **Objective:** Demonstrate what a malicious server can accomplish against a naive prototype ("Weak Mode") versus the hardened RatchetChat implementation ("Secure Mode").
- **Methodology:**
  - Mallory intercepts Alice's request for Bob's prekey bundle and returns Mallory's own public keys.
  - **Weak Mode:** Alice ignores Ed25519 signatures on Signed Prekeys ($SPK$) and skips Safety Number comparison.
  - **Secure Mode:** Alice enforces Ed25519 signature verification and calculates 60-digit Safety Numbers.
- **Empirical Comparison:**

```
+---------------------------------------------------------------------------------------------+
|                                    MITM ATTACK OUTCOME                                      |
+--------------------------------------------------+------------------------------------------+
|            WEAK MODE (VULNERABLE)                |         SECURE MODE (HARDENED)           |
+--------------------------------------------------+------------------------------------------+
| 1. Alice accepts Mallory's unsigned prekeys.     | 1. Alice checks Bob's Ed25519 signature. |
| 2. Alice computes X3DH master key with Mallory.  |    -> Fails immediately if forged!       |
| 3. Mallory intercepts & decrypts Alice's message:|                                          |
|    "Exam Questions: Midterm 2 Solution"          | 2. If Mallory presents self-signed bundle|
| 4. Mallory modifies text and forwards to Bob.    |    Alice & Bob compute Safety Numbers:   |
| 5. Bob reads tampered message completely unaware |    - Alice View: 05878 07018 59731...    |
|                                                  |    - Bob View:   03973 64820 44132...    |
| RESULT: Active MitM succeeds silently!           |                                          |
| [✗] Confidentiality & Integrity BROKEN           | RESULT: Fingerprint mismatch detected!   |
|                                                  | [🛡️] Red Security Alert halts chat!     |
+--------------------------------------------------+------------------------------------------+
```

---

## 4. Performance Benchmarks

All benchmarks were executed on Node.js v24.14.0 using high-resolution hardware timers (`perf_hooks.performance.now()`).

### 4.1 Asynchronous Key Agreement (X3DH) Latency

| Operation | Details | Latency (ms) |
| :--- | :--- | :---: |
| **Prekey Bundle Generation** | 1x Ed25519 IK, 1x X25519 IK, 1x X25519 SPK + Ed25519 Sig, 20x X25519 OPKs | **19.416 ms** |
| **Alice Initiation** | Verify Ed25519 Sig + 4x X25519 ECDH + HKDF-SHA256 | **14.364 ms** |
| **Bob Handshake Reception** | OPK lookup + 4x X25519 ECDH + HKDF-SHA256 | **27.559 ms** |
| **Total Asynchronous Handshake Overhead** | Complete end-to-end cryptographic setup | **41.923 ms** |

*Analysis:* A one-time initial handshake overhead of ~42 ms is completely imperceptible to end-users (human perception threshold is ~100 ms), confirming that X3DH introduces virtually zero perceptible delay.

---

### 4.2 Double Ratchet Per-Message Latency & Throughput

| Payload Size | Message Type | Encrypt Time (ms) | Decrypt Time (ms) | Throughput (msgs/sec) |
| :--- | :--- | :---: | :---: | :---: |
| **64 Bytes** | Short Text / Chat Ping | 0.428 ms | 0.420 ms | **1,179 msgs/sec** |
| **1 KB** | Standard Conversational Message | 0.497 ms | 0.465 ms | **1,040 msgs/sec** |
| **10 KB** | Long Paragraph / Code Snippet | 1.637 ms | 1.659 ms | **303 msgs/sec** |
| **100 KB** | Large Formatted Document | 17.492 ms | 18.098 ms | **28 msgs/sec** |

*Analysis:* For standard chat payloads (64B to 1KB), encryption and decryption each execute in **under 0.5 milliseconds**, achieving a sustained throughput exceeding **1,000 messages per second** per client thread.

---

## 5. Forward Secrecy & Break-in Recovery Analysis

### 5.1 Mathematical Proof of Forward Secrecy (FS)
- Let $CK_i$ be the sending chain key at index $i$.
- To derive the message key $MK_i$ and the next chain key $CK_{i+1}$, the protocol computes:
  $$CK_{i+1} \parallel MK_i = \text{HKDF}(CK_i, \text{salt}=0^{32}, \text{info}, 64)$$
- HKDF is constructed from HMAC-SHA256, which acts as a cryptographically secure pseudorandom function (PRF).
- **One-Way Invariant:** Computing $CK_i$ from $CK_{i+1}$ requires inverting the compression function of SHA-256, which has computational complexity $\mathcal{O}(2^{256})$.
- **Empirical Validation:** When $CK_{N}$ was extracted and supplied to the decryption pipeline, attempts to decrypt messages $0 \dots N-1$ failed 100% of the time. Compromising current state reveals zero past messages.

### 5.2 Mathematical Proof of Post-Compromise Security (Break-in Recovery)
- Assume an adversary captures the complete client memory at step $t$, obtaining $\{ RK_t, CK_{s, t}, CK_{r, t} \}$.
- Upon the subsequent conversational turn, Bob generates a new ephemeral key pair $DH_{B, t+1}$ and transmits public key $DHR_{B, t+1}$.
- Alice generates a fresh private key $DH_{A, t+1}^{priv}$ and computes:
  $$SS = \text{ECDH}(DH_{A, t+1}^{priv}, DHR_{B, t+1}^{pub})$$
  $$RK_{t+1}, CK_{s, t+1} = \text{HKDF}(SS, RK_t, \text{"RootStep"}, 64)$$
- The adversary lacks $DH_{A, t+1}^{priv}$ and $DH_{B, t+1}^{priv}$. Computing $SS$ from the observed public keys is the Computational Diffie-Hellman (CDH) problem on Curve25519, which is computationally intractable ($\approx 2^{128}$ security level).
- **Empirical Validation:** As demonstrated in Benchmark 3, the adversary's stolen state at step $t$ completely failed to decrypt messages at step $t+1$. The session healed itself autonomously.

---

## 6. Course Learning Outcomes (CS3002) Alignment

This project directly demonstrates mastery of the concepts outlined in the **CS3002 Information Security** syllabus:

1. **Symmetric Cryptography (Lectures 5-6):** Implementation of AES-256-GCM; empirical validation of block cipher modes, initialization vector uniqueness, and AEAD Galois counter tags.
2. **Asymmetric Cryptography (Lectures 7-8):** Application of Curve25519 (X25519); theoretical and empirical analysis of Man-in-the-Middle attacks against unauthenticated Diffie-Hellman.
3. **Cryptographic Integrity & Digital Signatures (Lectures 9-10):** RFC 5869 HKDF key expansion; Ed25519 digital signatures on prekeys; SHA-512 iterated hashing for Safety Numbers.
4. **Security Design Principles (Lecture 2):**
   - *Least Privilege & Complete Mediation:* Relay server handles only opaque ciphertexts.
   - *Fail-Safe Defaults:* Any tag or signature discrepancy defaults to total message rejection.
   - *Economy of Mechanism:* Standardized, vetted cryptographic primitives; zero invented ciphers.
   - *Defense in Depth:* TLS in transit + End-to-End Double Ratchet encryption + Out-of-band Safety Numbers.
5. **Security Operations & Analysis (Lectures 22, 24):** Creation of an interactive attack lab, live packet inspection, and rigorous empirical measurement.

---

## 7. Limitations & Future Scope

While RatchetChat provides provable confidentiality, integrity, forward secrecy, and break-in recovery, the following limitations are noted:

1. **Metadata Leakage:** The relay server observes communication graphs (who is communicating with whom, message timestamps, packet lengths). Countermeasures such as mixnets (e.g., Tor, Loopix) or constant-size packet padding can be explored in future revisions.
2. **Group Messaging:** The current implementation is scoped to 1-to-1 conversations. Expanding to group chats requires implementing the **Sender Keys Protocol** or **TreeKEM (MLS - Messaging Layer Security)**.
3. **Voice / Video & Large Files:** The prototype focuses on textual payloads. Encrypted chunked streaming for audio/video calls via WebRTC SRTP can be added as a future module.

---

## 8. Lessons Learned

1. **Protocol Invariants Over Cipher Strength:** Attacks against modern cryptography almost never target the underlying AES or ECC mathematics; vulnerabilities arise in key exchange orchestration, lack of prekey signatures, or improper state cleanup.
2. **Memory Zeroization is Paramount:** Forward secrecy is theoretical unless message keys are actively expunged from memory immediately after use.
3. **Usability of Key Verification:** Mathematical security against MitM is ineffective if users cannot easily compare fingerprints. Formatting the SHA-512 digest into distinct 5-digit chunks (Signal format) significantly reduces visual fatigue and error rates during verification.

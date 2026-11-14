# RatchetChat: End-to-End Encrypted Messaging with Forward Secrecy & Attack Demonstration Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/Node.js-v18%2B-brightgreen.svg)](https://nodejs.org/)
[![Course](https://img.shields.io/badge/Course-CS3002%20Information%20Security-orange.svg)](#)
[![Status](https://img.shields.io/badge/Status-Completed%20%26%20Evaluated-success.svg)](#)

> **Information Security Course Project (Fall 2026)**  
> **Institution:** National University of Computer & Emerging Sciences (FAST-NUCES)  
> **Instructor:** Dr. Ammar Haider  
> **Student:** Usman Wajid (Roll No: **23L-6038**, Section BCS-7A)  
> **Repository:** [https://github.com/usmanwajid09/RatchetChat.git](https://github.com/usmanwajid09/RatchetChat.git)

---

## 📌 1. Project Overview

**RatchetChat** is a production-grade, zero-knowledge End-to-End Encrypted (E2EE) messaging application implementing the **Signal Protocol specification**. In traditional web platforms, intermediate relay servers terminate TLS, allowing the server operator or a database intruder to read plaintext messages. RatchetChat eliminates this vulnerability by ensuring that **all key generation, asymmetric handshakes, per-message ratcheting, encryption, and decryption occur exclusively within the client browser sandbox**.

The relay server acts solely as an untrusted ciphertext switchboard and public prekey directory: it possesses **zero private keys** and cannot decrypt transmitted messages under any circumstances.

### Core Security Properties
- **Asymmetric Asynchronous Key Agreement (X3DH):** Allows two parties to establish a shared master secret even if the recipient is offline, utilizing Curve25519 (X25519 & Ed25519).
- **Double Ratchet (Forward Secrecy & Break-in Recovery):** 
  - **Symmetric KDF Ratchet:** Advances the key on every message, guaranteeing that stolen keys cannot decrypt past messages (**Forward Secrecy**).
  - **Diffie-Hellman Ratchet:** Steps on every conversational turn, ensuring that compromised internal state heals automatically on the very next response (**Post-Compromise Security**).
- **Authenticated Encryption with Associated Data (AEAD):** **AES-256-GCM** with 96-bit unique IVs and 128-bit authentication tags cryptographically binding headers and identities.
- **Safety Numbers (Cryptographic Fingerprints):** 12 blocks of 5-digit decimal numbers (60 digits total, identical to Signal's format) derived via iterated SHA-512 hashing to defeat Man-in-the-Middle (MitM) attacks.
- **Interactive Attacker Toolkit:** Live CLI scripts and an in-browser **Attack Lab** demonstrating passive sniffing, ciphertext tampering/replay, and server MitM key substitution against both a vulnerable **Weak Mode** and a hardened **Secure Mode**.

---

## 🏗️ 2. Cryptographic Stack

| Cryptographic Primitive | Implementation | Purpose |
| :--- | :--- | :--- |
| **X25519 ECDH** | `@noble/curves` / WebCrypto | Key agreement for X3DH & DH Ratchet steps |
| **Ed25519 Digital Signatures** | `@noble/curves` / WebCrypto | Authenticating Signed Prekeys ($SPK$) |
| **AES-256-GCM** | Web Crypto API (`subtle`) | Authenticated message encryption & integrity |
| **HKDF-SHA256** | Web Crypto API (RFC 5869) | Root, chain, and message key derivations |
| **SHA-512 & SHA-256** | Web Crypto API / FIPS 180-4 | 60-digit Safety Number fingerprint derivation |
| **Constant-Time Comparison** | Bitwise reduction $\mathcal{O}(n)$ | Protection against timing side-channel attacks |

---

## 📂 3. Repository Structure

```text
RatchetChat/
├── server/                            # Relay Server (Node.js & Express)
│   ├── index.js                       # HTTP & Socket.io server entry point
│   ├── database.js                    # Dual DB: MongoDB + embedded JSON fallback
│   ├── routes/
│   │   ├── auth.js                    # User registration, login & session tokens
│   │   ├── prekeys.js                 # Prekey bundle directory (IK, SPK, OPKs)
│   │   ├── messages.js                # Offline ciphertext queue & mailbox
│   │   └── admin.js                   # Live packet inspector & MitM toggle API
│   ├── sockets/
│   │   └── chatHandler.js             # Transparent WebSocket message relay
│   └── middleware/
│       └── authMiddleware.js          # JWT session authentication
├── client/                            # Web Application Sandbox
│   ├── index.html                     # Responsive Single Page Application
│   ├── css/style.css                  # Modern dark/light UI styling
│   └── js/
│       ├── crypto/
│       │   ├── noble-curves.js        # Self-contained Curve25519 bundle (36KB)
│       │   ├── primitives.js          # AES-256-GCM, HKDF, SHA-512, CSPRNG
│       │   ├── x3dh.js                # X3DH protocol implementation
│       │   ├── double_ratchet.js      # Double Ratchet (DH + Symmetric chains)
│       │   ├── safety_number.js       # 60-digit Signal fingerprint generator
│       │   └── keystore.js            # Secure browser key storage (private keys stay local)
│       ├── api.js                     # REST API client
│       ├── socket.js                  # Socket.io client wrapper
│       ├── chat.js                    # Cryptographic session coordinator
│       ├── ui.js                      # UI controller, modals & event bindings
│       └── attack_lab.js              # Interactive in-browser Attack Lab
├── attack_toolkit/                    # Automated Attack Evaluation Scripts
│   ├── eavesdrop_attack.js            # Attack 1: Passive sniffing & DB dump analysis
│   ├── tamper_replay_attack.js        # Attack 2: Bit-flipping & packet replay injection
│   └── mitm_attack.js                 # Attack 3: Active MitM Key Substitution simulation
├── benchmarks/
│   └── run_benchmarks.js              # Benchmarking suite (latency & throughput)
├── tests/
│   ├── x3dh.test.js                   # X3DH unit tests (5/5 passed)
│   ├── double_ratchet.test.js         # Double Ratchet unit tests (6/6 passed)
│   ├── safety_number.test.js          # Safety number unit tests (5/5 passed)
│   └── end_to_end.test.js             # Full end-to-end integration tests (8/8 passed)
├── docs/
│   ├── ARCHITECTURE.md                # In-depth architectural & protocol specification
│   └── SECURITY_ANALYSIS.md           # Formal security analysis & empirical benchmarks
├── package.json
└── README.md                          # Execution & evaluation manual
```

---

## 🚀 4. Quick Start & Running Instructions

### 4.1 Prerequisites
- **Node.js** v18.0.0 or higher ([Download Node.js](https://nodejs.org/))
- **npm** (included with Node.js)
- *Note:* A local MongoDB installation is **optional**. The server includes an integrated, zero-dependency persistent JSON database engine that activates automatically if MongoDB is not detected.

### 4.2 Installation
Clone the repository and install dependencies:
```bash
git clone https://github.com/usmanwajid09/RatchetChat.git
cd RatchetChat
npm install
```

### 4.3 Start the Relay Server
```bash
npm start
```
The server will initialize and display:
```text
=======================================================
 RatchetChat Relay Server is running on port 3001
 Open Web Client: http://localhost:3001
 Status: http://localhost:3001/api/health
=======================================================
```

---

## 💻 5. Class Evaluation & Live Testing Workflow

To test the application in an evaluation session:

### Step 1: Open Two Client Windows
1. Open your browser to `http://localhost:3001` (Window 1).
2. Open an Incognito window or second browser (Chrome/Firefox) to `http://localhost:3001` (Window 2).

### Step 2: Instant 1-Click Login
- In **Window 1**, click the quick account button: **Alice (Initiator)**.
- In **Window 2**, click the quick account button: **Bob (Recipient)**.
- *Notice:* The browser automatically generates Ed25519 identity keys, X25519 signed prekeys, and 20 one-time prekeys (OPKs), publishing the public bundle to the relay server. Private keys remain strictly inside the browser.

### Step 3: Send an End-to-End Encrypted Message
- In Alice's window, select **Bob** from the contacts list and send: `"Hello Bob, this is encrypted with Signal Double Ratchet!"`.
- In Bob's window, observe the message decrypt in real time (<0.5 ms).
- **Inspect Cryptographic Wire Data:** Click on any message bubble to open the **Cryptographic Packet Details Modal**, showing the raw AES-256-GCM ciphertext, 96-bit IV, and Ratchet Header ($N$, $PN$, $DHR$).

### Step 4: Verify Safety Numbers (MitM Defense)
- In both Alice and Bob's windows, click the **"🛡️ Safety Number"** button in the top bar.
- Compare the 60-digit numbers (12 blocks of 5 decimal digits). Observe that both clients derive the exact same numbers.
- Check **"Mark as Verified"** to confirm the contact.

---

## 🧪 6. Attacker Demonstration Toolkit

RatchetChat includes both an in-browser **Attack Lab** tab and standalone CLI scripts.

### Attack 1: Passive Sniffing & Database Extraction
Tests whether an eavesdropper or rogue server admin can extract plaintexts.
```bash
npm run attack:sniff
```
- **Finding:** Yields Shannon entropy of **7.989 bits/byte** (pure pseudorandom noise). **Zero plaintext bytes leaked**.

### Attack 2: Ciphertext Bit-Flipping & Packet Replay
Demonstrates AES-256-GCM tag verification and replay counter defense.
```bash
npm run attack:tamper
```
- **Finding:** **100% of bit-flip attempts rejected** by GMAC authentication tag verification. Replayed packets are dropped.

### Attack 3: Man-in-the-Middle (MitM) Key Substitution
Compares a vulnerable "Weak Mode" against the hardened "Secure Mode".
```bash
npm run attack:mitm
```
- **Weak Mode:** Mallory intercepts, decrypts, tampers with, and forwards messages without detection.
- **Secure Mode:** Mallory's forged signed prekey is rejected by Ed25519 signature checks, and Safety Numbers diverge immediately (`05878 07018...` vs `03973 64820...`), triggering a red security alert.

---

## 📊 7. Automated Test Suite & Benchmarks

### Run All Unit & Integration Tests (24/24 Assertions Passed)
```bash
npm test
```
```text
[TEST] Running X3DH Protocol Test Suite...
[PASS] X3DH Protocol Test Suite: 5/5 assertions passed.
[TEST] Running Double Ratchet Test Suite...
[PASS] Double Ratchet Test Suite: 6/6 assertions passed.
[TEST] Running Safety Number Test Suite...
[PASS] Safety Number Test Suite: 5/5 assertions passed.
[TEST] Running End-to-End Integration Test Suite...
[PASS] End-to-End Integration Suite: 8/8 assertions passed.
```

### Run Performance Benchmarks
```bash
npm run benchmark
```
- **X3DH Handshake Overhead:** ~41.9 ms (total round-trip setup).
- **Encryption / Decryption Latency:** **0.428 ms / 0.420 ms** per message.
- **Throughput:** Exceeds **1,000 messages / second**.
- **Forward Secrecy & Post-Compromise Recovery:** Mathematically proven and empirically validated.

---

## 📄 8. Documentation

- 📘 **[Architecture & Protocol Specification (ARCHITECTURE.md)](docs/ARCHITECTURE.md):** Complete technical breakdown, state machines, sequence diagrams, and key derivation trees.
- 🔬 **[Security Analysis & Benchmark Report (SECURITY_ANALYSIS.md)](docs/SECURITY_ANALYSIS.md):** Threat modeling, empirical attack findings, benchmark tables, and discussion of course learning outcomes.

---

## 👤 Author & Acknowledgments

- **Student:** Usman Wajid (Roll No: **23L-6038**, Section BCS-7A)
- **Course:** CS3002: Information Security, Department of Computer Science
- **Instructor:** Dr. Ammar Haider
- **Institution:** National University of Computer and Emerging Sciences (FAST-NUCES)

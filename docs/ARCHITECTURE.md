# RatchetChat: Architecture & Protocol Specification
**End-to-End Encrypted Messaging with Forward Secrecy & Attack Demonstration Toolkit**

- **Course:** CS3002: Information Security (Fall 2026), FAST-NUCES
- **Instructor:** Dr. Ammar Haider
- **Author:** Usman Wajid (Roll No: 23L-6038, Section BCS-7A)
- **Repository:** [https://github.com/usmanwajid09/RatchetChat.git](https://github.com/usmanwajid09/RatchetChat.git)

---

## 1. System Overview & Design Philosophy

Traditional messaging platforms terminate Transport Layer Security (TLS) at intermediate relay servers. While TLS protects packets in transit across the public internet, the cloud server decrypts the payload into memory and can inspect, store, or be compelled to yield user communications. 

**RatchetChat** implements a **Zero-Knowledge End-to-End Encrypted (E2EE)** architecture modeled on the **Signal Protocol**. All cryptographic key generation, asymmetric handshakes, per-message key derivations, encryption, and decryption happen exclusively within the client browser sandbox. The server functions purely as an untrusted ciphertext switchboard and public prekey directory:
- The server never possesses any private keys or master secrets.
- The server cannot decrypt messages under any circumstances.
- Even in the event of a total server breach or database seizure, an adversary acquires only opaque ciphertext blobs and public keys.

---

## 2. Core Cryptographic Primitives

The system utilizes audited, standardized cryptographic primitives adhering to modern NIST and RFC standards:

| Primitive | Standard / Algorithm | Parameters / Curve | Primary Security Role |
| :--- | :--- | :--- | :--- |
| **Asymmetric Key Exchange** | X25519 (ECDH) | Curve25519 (RFC 7748), 256-bit | Triple Diffie-Hellman (X3DH) & Double Ratchet DH steps |
| **Digital Signatures** | Ed25519 (EdDSA) | Edwards-curve Digital Signature (RFC 8032) | Authenticating Signed Prekeys ($SPK$) to defeat MitM |
| **Authenticated Encryption** | AES-256-GCM | 256-bit Key, 96-bit random IV, 128-bit GMAC Tag | Message Confidentiality, Integrity, and Authenticity |
| **Key Derivation (KDF)** | HKDF-SHA256 | RFC 5869 Extract-and-Expand | Deriving Root Keys, Chain Keys, and Message Keys |
| **Cryptographic Hashing** | SHA-256 & SHA-512 | FIPS 180-4 Secure Hash Standard | Associated Data digests & 60-digit Safety Numbers |
| **Constant-Time Comparison** | Bitwise XOR Reduction | Constant execution time $\mathcal{O}(n)$ | Side-channel timing attack mitigation |

---

## 3. Threat Model & Trust Boundaries

The security posture of RatchetChat is formalized under the **Dolev-Yao Adversary Model**:

```
+-----------------------------------------------------------------------------------+
|                              UNTRUSTED ENVIRONMENT                                |
|                                                                                   |
|  [Alice Browser Sandbox]          [Untrusted Relay]          [Bob Browser Sandbox]|
|  +--------------------+         +-------------------+        +--------------------+
|  | Private Keys (RAM) |         | Prekey Directory  |        | Private Keys (RAM) |
|  | KeyStore (Local)   | <=====> | Ciphertext Queue  | <====> | KeyStore (Local)   |
|  | Crypto Engine      |         | Database (Opaque) |        | Crypto Engine      |
|  +--------------------+         +-------------------+        +--------------------+
|           ^                               ^                             ^         |
|           |                               |                             |         |
|   TRUST BOUNDARY 1                TRUST BOUNDARY 2              TRUST BOUNDARY 3  |
|   (Client Boundary)               (Relay Boundary)              (Client Boundary) |
|                                                                                   |
|  ADVERSARY CAPABILITIES (Mallory):                                                |
|  - Full control over transmission channel (sniff, drop, delay, tamper, replay).   |
|  - Compromised or malicious server administrator (database dumps, key spoofing).  |
+-----------------------------------------------------------------------------------+
```

### Trust Assumptions:
1. **Endpoint Integrity:** The user's device and browser environment are trusted. Memory scraping via hardware compromise or host-level kernel rootkits is outside the application boundary.
2. **Untrusted Server:** The relay server is assumed to be **honest-but-curious** at best, or **actively malicious (Mallory)** at worst. The protocol must guarantee confidentiality and detect key tampering regardless of server behavior.
3. **Network Hostility:** All intermediate networks (ISPs, proxies, public Wi-Fi) are actively monitored and adversarial.

---

## 4. Key Agreement: X3DH Protocol

The **Extended Triple Diffie-Hellman (X3DH)** protocol allows Alice to establish a secure shared master secret with Bob even if Bob is offline.

### 4.1 Key Structures
- **Identity Key ($IK$):** Long-term key pair. $IK_{sign}$ (Ed25519) and $IK_{dh}$ (X25519).
- **Signed Prekey ($SPK$):** Medium-term X25519 key pair, accompanied by an Ed25519 signature:
  $$\text{Sig}_{SPK} = \text{Sign}_{IK_{sign}}(SPK_{pub})$$
- **One-Time Prekeys ($OPK_1, \dots, OPK_n$):** Pool of single-use X25519 keys. The server yields exactly one OPK per session and deletes it immediately upon retrieval.
- **Ephemeral Key ($EK_A$):** Generated anew by Alice for every handshake initiation.

### 4.2 Handshake Computation
When Alice initiates contact with Bob:
1. Alice requests Bob's Prekey Bundle from the server: $\{ IK_B, SPK_B, \text{Sig}_{SPK}, OPK_B^i \}$.
2. Alice verifies Bob's signature on $SPK_B$:
   $$\text{Verify}(IK_{B, sign}, SPK_{B, pub}, \text{Sig}_{SPK}) \stackrel{?}{=} \text{True}$$
3. Alice computes four Diffie-Hellman outputs:
   $$\begin{aligned}
   DH_1 &= \text{ECDH}(IK_{A, dh}^{priv}, SPK_{B}^{pub}) \\
   DH_2 &= \text{ECDH}(EK_{A}^{priv}, IK_{B, dh}^{pub}) \\
   DH_3 &= \text{ECDH}(EK_{A}^{priv}, SPK_{B}^{pub}) \\
   DH_4 &= \text{ECDH}(EK_{A}^{priv}, OPK_{B}^{pub})
   \end{aligned}$$
4. Alice derives the Shared Master Secret ($SK$):
   $$SK = \text{HKDF-Extract-and-Expand}(DH_1 \parallel DH_2 \parallel DH_3 \parallel DH_4, \text{salt}=0^{32}, \text{info}=\text{"RatchetChat-X3DH-MasterSecret-v1"}, 32)$$
5. Alice constructs Associated Data ($AD$) binding the public identities:
   $$AD = IK_{A, sign}^{pub} \parallel IK_{B, sign}^{pub}$$
6. Alice sends her initial message containing $\{ IK_{A}, EK_{A}, \text{UsedOpkId}, \text{Ciphertext} \}$.
7. Upon receipt, Bob executes the matching private-key operations, derives the identical $SK$, and immediately deletes $OPK_B^i$.

---

## 5. Message Encryption: Double Ratchet Algorithm

Once $SK$ is established, the session transitions into the **Double Ratchet**, combining a symmetric KDF ratchet and an asymmetric Diffie-Hellman ratchet.

### 5.1 Symmetric KDF Ratchet (Forward Secrecy)
For every message sent or received within a turn, the symmetric chain key advances:
$$\begin{aligned}
CK_{i+1}, MK_i &= \text{HKDF}(CK_i, \text{salt}=0^{32}, \text{info}=\text{"RatchetChat-DoubleRatchet-ChainStep-v1"}, 64) \\
\text{where } &CK_{i+1} = \text{derived}[0 \dots 31] \quad (\text{Next Chain Key}) \\
&MK_i = \text{derived}[32 \dots 63] \quad (\text{Message Encryption Key})
\end{aligned}$$
- Message Key $MK_i$ is used to encrypt the payload with **AES-256-GCM** and is erased from memory immediately after encryption/decryption.
- **Forward Secrecy Guarantee:** Because HKDF is a one-way pseudorandom function, compromise of $CK_{i+1}$ cannot invert to reveal $CK_i$ or past message keys $MK_{0 \dots i}$.

### 5.2 Diffie-Hellman Ratchet (Post-Compromise Security / Break-in Recovery)
Whenever a participant receives a response containing a new DH ratchet public key ($DHR$):
1. Missed messages in the previous chain are skipped and cached.
2. A two-step DH ratchet is executed:
   $$\begin{aligned}
   \text{Step 1 (Receiving Chain): } & RK, CK_r = \text{HKDF}(\text{ECDH}(DH_{s, old}^{priv}, DHR_{new}^{pub}), RK_{old}, \text{info}=\text{"RootStep"}, 64) \\
   \text{Generate New Local DH: } & DH_{s, new} = \text{GenerateX25519KeyPair}() \\
   \text{Step 2 (Sending Chain): } & RK, CK_s = \text{HKDF}(\text{ECDH}(DH_{s, new}^{priv}, DHR_{new}^{pub}), RK, \text{info}=\text{"RootStep"}, 64)
   \end{aligned}$$
3. **Break-in Recovery Guarantee:** If an adversary compromises Alice's internal state at time $t$, future messages become completely unreadable as soon as Bob responds with a fresh DH key, restoring full cryptographic secrecy.

### 5.3 Out-of-Order Delivery & Replay Resistance
- Messages carry sequence number $N$ and previous chain length $PN$.
- If packet $N+2$ arrives before $N$, the receiver calculates and caches $MK_N$ and $MK_{N+1}$ in a bounded LRU cache (`MKSKIPPED`, max 1000 keys).
- When a delayed packet arrives, it is decrypted using its cached key, and the key is immediately erased.
- Duplicate packets are rejected because the key no longer exists and sequence counter validation fails.

---

## 6. Safety Numbers (Identity Fingerprints)

To prevent active Man-in-the-Middle attacks (such as a malicious relay substituting public keys):
1. Alice and Bob's long-term Ed25519 identity public keys are sorted deterministically:
   $$\text{Sorted} = \text{sort}(IK_{A, sign}, IK_{B, sign})$$
2. Iterated cryptographic hashing (1000 rounds of SHA-512) is performed to prevent brute-force precomputation:
   $$D_0 = \text{SHA-512}(IK_1 \parallel IK_2 \parallel \text{"RatchetChat-SafetyNumber-Fingerprint-v1"})$$
   $$D_{k} = \text{SHA-512}(D_{k-1}) \quad \text{for } k = 1 \dots 1000$$
3. The 64-byte digest is partitioned into twelve 32-bit unsigned integers:
   $$\text{Block}_j = \text{Uint32}(D[4j \dots 4j+3]) \pmod{100000} \quad \text{for } j = 0 \dots 11$$
4. Each block is formatted as a 5-digit decimal string, producing **12 blocks of 5 digits (60 digits total)** matching the Signal specification.
5. Users compare these numbers out-of-band. Any divergence indicates key substitution.

---

## 7. Component Architecture

```
+------------------------------------------------------------------------------------+
|                                CLIENT APPLICATION                                  |
|                                                                                    |
|  +--------------------+  +----------------------+  +----------------------------+  |
|  |      UI Layer      |  |   Chat Orchestrator  |  |    Cryptographic Engine    |  |
|  | - Single Page App  |  | - Session Management |  | - primitives.js            |  |
|  | - Chat View        |  | - X3DH Flow (chat.js)|  | - x3dh.js                  |  |
|  | - Attack Lab View  |  | - Ratchet State Sync |  | - double_ratchet.js        |  |
|  | - Packet Inspector |  | - KeyStore (Local)   |  | - safety_number.js         |  |
|  +--------------------+  +----------------------+  +----------------------------+  |
|            |                        |                            |                 |
+------------|------------------------|----------------------------|-----------------+
             |                        |                            |
             | REST API / WebSocket   | Ciphertext Payload         |
             v                        v                            v
+------------------------------------------------------------------------------------+
|                         RELAY SERVER (Node.js & Express)                           |
|                                                                                    |
|  +--------------------+  +----------------------+  +----------------------------+  |
|  |  Socket.io Relay   |  |     REST Router      |  |     Dual Database Engine   |  |
|  | - Real-time stream |  | - /api/auth          |  | - MongoDB (via Mongoose)   |  |
|  | - Offline fallback |  | - /api/prekeys       |  | - Embedded JSON Fallback   |  |
|  | - Inspector hook   |  | - /api/messages      |  | - Prekey & Mailbox store   |  |
|  |                    |  | - /api/admin         |  |                            |  |
|  +--------------------+  +----------------------+  +----------------------------+  |
+------------------------------------------------------------------------------------+
```

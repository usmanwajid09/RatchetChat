"""
Script to generate the formal academic project report in DOCX format
for Usman Wajid (23L-6038) - CS3002 Information Security.
"""

import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT

doc = docx.Document()

# Adjust margins
sections = doc.sections
for section in sections:
    section.top_margin = Inches(1)
    section.bottom_margin = Inches(1)
    section.left_margin = Inches(1)
    section.right_margin = Inches(1)

# Title & Metadata
title = doc.add_paragraph()
title_run = title.add_run("RATCHETCHAT: END-TO-END ENCRYPTED MESSAGING WITH FORWARD SECRECY")
title_run.bold = True
title_run.font.size = Pt(20)
title_run.font.color.rgb = RGBColor(14, 116, 144)
title.alignment = WD_ALIGN_PARAGRAPH.CENTER

subtitle = doc.add_paragraph()
sub_run = subtitle.add_run("Signal Protocol Implementation & Attacker Demonstration Toolkit\nFinal Project Report & Security Analysis")
sub_run.font.size = Pt(13)
sub_run.italic = True
subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER

p_meta = doc.add_paragraph()
p_meta.add_run("\nCourse: ").bold = True
p_meta.add_run("CS3002: Information Security (Fall 2026)\n")
p_meta.add_run("Instructor: ").bold = True
p_meta.add_run("Dr. Ammar Haider\n")
p_meta.add_run("Student Name: ").bold = True
p_meta.add_run("Usman Wajid (Individual Project)\n")
p_meta.add_run("Roll Number: ").bold = True
p_meta.add_run("23L-6038\n")
p_meta.add_run("Section: ").bold = True
p_meta.add_run("BCS-7A\n")
p_meta.add_run("Institution: ").bold = True
p_meta.add_run("FAST - National University of Computer and Emerging Sciences\n")
p_meta.add_run("GitHub Repository: ").bold = True
p_meta.add_run("https://github.com/usmanwajid09/RatchetChat.git\n")

doc.add_heading("1. Executive Summary", level=1)
doc.add_paragraph(
    "Most contemporary messaging platforms terminate Transport Layer Security (TLS) at intermediate relay servers. "
    "Consequently, the server operator, compromised infrastructure, or subpoenaed database dumps can expose user communications. "
    "RatchetChat resolves this fundamental architectural vulnerability by implementing a zero-knowledge End-to-End Encrypted (E2EE) "
    "messaging system adhering to the Signal Protocol specification. All cryptographic key generation, asymmetric handshakes, per-message "
    "key ratcheting, encryption, and decryption are executed strictly within the client browser environment. The Node.js/Express relay "
    "server handles purely opaque ciphertext and stores public prekeys; it never possesses private keys or plaintext."
)

doc.add_heading("2. Core Cryptographic Architecture", level=1)
doc.add_paragraph(
    "The system is built upon four mathematically sound cryptographic foundations:\n"
    "1. Asymmetric Key Agreement (X3DH): Employs Curve25519 (X25519 ECDH and Ed25519 signatures) to establish an initial master shared secret "
    "between two parties even when the recipient is offline. A 4-way Diffie-Hellman derivation (DH1, DH2, DH3, DH4) binds the long-term identity keys, "
    "signed prekeys, and one-time prekeys (OPKs).\n"
    "2. Double Ratchet Algorithm: Combines a symmetric KDF ratchet (HKDF-SHA256) advancing per message to provide Forward Secrecy (FS) with an "
    "asymmetric Diffie-Hellman ratchet advancing per conversational turn to provide Break-in Recovery (Post-Compromise Security).\n"
    "3. Authenticated Encryption (AEAD): Encrypts messages using AES-256-GCM with unique 96-bit random IVs and 128-bit authentication tags binding "
    "ratchet headers and identity parameters as Associated Data (AD).\n"
    "4. Out-of-Band Verification (Safety Numbers): Derives a 60-digit decimal fingerprint (12 blocks of 5 digits, matching Signal's format) via "
    "1,000 rounds of SHA-512 hashing of sorted identity keys, enabling participants to visually detect active Man-in-the-Middle (MitM) proxies."
)

doc.add_heading("3. Attacker Demonstration Toolkit & Empirical Results", level=1)
doc.add_paragraph(
    "To validate the system's defenses, an automated Attacker Toolkit was developed and tested against both a hardened 'Secure Mode' "
    "and a deliberately vulnerable 'Weak Mode':"
)

# Table for Attacks
t_attacks = doc.add_table(rows=1, cols=4)
t_attacks.alignment = WD_TABLE_ALIGNMENT.CENTER
hdr_cells = t_attacks.rows[0].cells
hdr_cells[0].text = "Attack Scenario"
hdr_cells[1].text = "Threat Model"
hdr_cells[2].text = "Weak Mode Outcome"
hdr_cells[3].text = "Secure Mode Outcome"

data = [
    ("Attack 1: Passive Sniffing", "Passive wiretap & server DB dump", "Ciphertext opaque (0% plaintext leaked)", "100% Confidentiality preserved (Shannon entropy: 7.989 bits/byte)"),
    ("Attack 2A: Bit-Flip Tampering", "Active network modifier", "Silent acceptance / corruption", "100% Rejection via AES-256-GCM GMAC tag failure"),
    ("Attack 2B: Packet Replay", "Active network replay injector", "Duplicate processed", "100% Rejection: Ratchet advanced, old key zeroized"),
    ("Attack 3: MitM Key Substitution", "Rogue server substituting prekeys", "Mallory decrypts & tampers messages", "BLOCKED: Ed25519 signature fails or Safety Numbers diverge")
]

for row in data:
    row_cells = t_attacks.add_row().cells
    for i, val in enumerate(row):
        row_cells[i].text = val

doc.add_heading("4. Performance Benchmarks", level=1)
doc.add_paragraph(
    "Benchmarks conducted on Node.js v24.14.0 using high-resolution hardware timers measured execution latency and throughput:"
)

t_bench = doc.add_table(rows=1, cols=4)
t_bench.alignment = WD_TABLE_ALIGNMENT.CENTER
b_hdr = t_bench.rows[0].cells
b_hdr[0].text = "Payload Size / Operation"
b_hdr[1].text = "Encryption (ms)"
b_hdr[2].text = "Decryption (ms)"
b_hdr[3].text = "Throughput / Result"

b_data = [
    ("X3DH Initial Handshake", "-", "-", "41.923 ms total setup"),
    ("64 Bytes (Short Chat)", "0.428 ms", "0.420 ms", "1,179 msgs/sec"),
    ("1 KB (Standard Message)", "0.497 ms", "0.465 ms", "1,040 msgs/sec"),
    ("10 KB (Code / Rich Text)", "1.637 ms", "1.659 ms", "303 msgs/sec"),
    ("100 KB (Large Document)", "17.492 ms", "18.098 ms", "28 msgs/sec"),
    ("Forward Secrecy Verification", "-", "-", "100% Invariant Pass (Historic keys zeroized)"),
    ("Post-Compromise Recovery", "-", "-", "100% Invariant Pass (Healed on turn N+1)")
]

for row in b_data:
    row_cells = t_bench.add_row().cells
    for i, val in enumerate(row):
        row_cells[i].text = val

doc.add_heading("5. Course Learning Outcomes Mapping", level=1)
doc.add_paragraph(
    "The project directly addresses the core competencies specified in the CS3002 Information Security syllabus:\n"
    "• Symmetric Cryptography (Lec 5-6): AES-256-GCM AEAD, IV management, and GMAC authentication.\n"
    "• Asymmetric Cryptography & DH (Lec 7-8): Curve25519 ECDH key agreement and MitM attack analysis.\n"
    "• Digital Signatures & Integrity (Lec 9-10): Ed25519 signatures, HKDF-SHA256, and SHA-512 fingerprints.\n"
    "• Security Principles (Lec 2): Least privilege, fail-safe defaults, economy of mechanism, and defense in depth."
)

doc.add_heading("6. Execution & Verification Instructions", level=1)
doc.add_paragraph(
    "1. Clone and Install:\n"
    "   git clone https://github.com/usmanwajid09/RatchetChat.git\n"
    "   cd RatchetChat\n"
    "   npm install\n\n"
    "2. Start Server:\n"
    "   npm start  (Runs on http://localhost:3001)\n\n"
    "3. Run Full Automated Test Suite (24/24 assertions):\n"
    "   npm test\n\n"
    "4. Run Performance Benchmarks:\n"
    "   npm run benchmark\n\n"
    "5. Run Attacker Demonstration Scripts:\n"
    "   npm run attack:sniff\n"
    "   npm run attack:tamper\n"
    "   npm run attack:mitm\n\n"
    "6. Interactive Browser Evaluation:\n"
    "   Open two browser windows to http://localhost:3001, click 'Alice' and 'Bob', chat in real time, click message bubbles to inspect wire payloads, and open the 'Attack Lab' tab to demonstrate attacks live."
)

doc.save("docs/l236038_Final_Project_Report.docx")
print("Successfully generated docs/l236038_Final_Project_Report.docx")


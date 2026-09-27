# CRYPTOTRACE

## Cryptographic Attribution and Immutable Decryption Provenance for Multi-Recipient Encrypted Document Distribution

**SIH 2026 — Problem Statement: SIH26237**  
**Theme:** Cybersecurity & Defence Technology  
**Category:** Software  
**Team:** CODEBREAKERS

---

## Overview

CRYPTOTRACE is a security-focused document distribution and forensic attribution system designed for situations where the same confidential document must be securely distributed to multiple authorized recipients.

The system combines:

- Post-quantum cryptography
- Recipient-specific decryption provenance
- Invisible watermarking
- Digital signatures
- Reed-Solomon error correction
- Tamper-evident hash-chain ledger
- Merkle inclusion proofs
- Role-based access control
- Clearance-based authorization
- Key lifecycle management
- Persistent SQLite storage
- Forensic evidence correlation

The primary goal is to provide **verifiable provenance evidence** when a distributed confidential document is later recovered outside its authorized environment.

> CRYPTOTRACE treats watermarking and ledger records as forensic evidence. It does not claim absolute attribution or an impossible-to-remove watermark.

---

# Problem

Consider a confidential government document distributed to 10 authorized officers.

All recipients may receive the same encrypted document, but later a leaked copy is discovered.

Traditional encryption can answer:

> "Who was authorized to receive this document?"

But it may not provide sufficient evidence to determine:

> "Which authorized recipient actually decrypted or released this particular copy?"

CRYPTOTRACE addresses this provenance gap by associating a recipient-specific decryption event with the resulting document copy.

---

# Core Concept

```text
                 CONFIDENTIAL DOCUMENT
                          |
                          v
                    SHA3-256 HASH
                          |
                          v
                  AES-256-GCM ENCRYPTION
                          |
                          v
                 ENCRYPTED CONTENT KEY
                          |
              +-----------+-----------+
              |           |           |
              v           v           v
           RECIPIENT A  RECIPIENT B  RECIPIENT C
              |           |           |
           ML-KEM       ML-KEM       ML-KEM
           WRAPPING     WRAPPING     WRAPPING
              |           |           |
              +-----------+-----------+
                          |
                          v
                 RECIPIENT DECRYPTION
                          |
                          v
                    UNIQUE EVENT ID
                          |
                          v
                 INVISIBLE WATERMARK
                          |
                          v
               REED-SOLOMON ECC
                          |
                          v
                 ML-DSA SIGNATURE
                          |
                          v
             TAMPER-EVIDENT LEDGER
                          |
                          v
                  FORENSIC ANALYSIS

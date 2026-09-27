# CRYPTOTRACE Phase 3: Persistent Storage, RBAC & Forensic Key Lifecycle

## 1. Phase 3 Architecture Overview

Phase 3 elevates CRYPTOTRACE from an ephemeral in-memory prototype to an enterprise-grade, persistent cryptographic system. All document distributions, cryptographic identities, key lifecycle states, sequential ledger blocks, Merkle batches, and audit trails are persisted deterministically in SQLite with strict foreign-key integrity and indexing.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           SECURITY & RBAC                               │
│  [ADMIN]           [SENDER]          [RECIPIENT]        [INVESTIGATOR]  │
│  Manage Identities  Distribute Docs   Decrypt Packages   Verify Leaks   │
│  Manage Roles       Check Clearance   Sign Attestation   Audit Proofs   │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
┌────────────────────────────────────▼────────────────────────────────────┐
│                       LOCAL ENCRYPTED KEYSTORE                          │
│  • PQC Secret Keys (ML-KEM-768, ML-DSA-65) encrypted with AES-256-GCM   │
│  • Master passphrase derived via SHA3-256 / HKDF                        │
│  • Zero plaintext private keys in SQLite database or logs               │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
┌────────────────────────────────────▼────────────────────────────────────┐
│                    SQLITE REPOSITORY / STORAGE LAYER                    │
│  • users                        • document_distributions                │
│  • cryptographic_identities     • decryption_events                     │
│  • documents                    • ledger_blocks (Sequential HashChain)  │
│  • merkle_batches               • audit_logs (Append-Only)              │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
┌────────────────────────────────────▼────────────────────────────────────┐
│                    TAMPER-EVIDENT FORENSIC VERIFICATION                 │
│  • Offline HashChain Integrity Check on Reload                          │
│  • Merkle Tree Batch Inclusion Proofs (Sha3Algorithm)                   │
│  • Historical Attestation Verifiability across Key Revocation           │
│  • Explainable Confidence & Forensic Audit Logging                      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Database Schema & Tables

The SQLite database (`packages/storage-sqlite`) initializes with `PRAGMA foreign_keys = ON` and WAL journal mode.

### Schema Summary:
| Table Name | Primary Key | Key Columns / Foreign Keys | Description |
| :--- | :--- | :--- | :--- |
| `users` | `user_id` | `clearance_level`, `role`, `department` | Canonical user identity and role assignment. |
| `cryptographic_identities` | `identity_id` | `user_id` (FK $\to$ `users`), `kem_public_key`, `dsa_public_key`, `status` | PQC public identities and lifecycle states. |
| `documents` | `document_id` | `document_hash` (UNIQUE), `classification`, `encrypted_data`, `doc_nonce` | Registered encrypted document records. |
| `document_distributions` | `id` | `document_id` (FK $\to$ `documents`), `recipient_identity_id`, `ml_kem_ciphertext`, `encrypted_content_key`, `wrapped_nonce` | Recipient-specific wrapped keys. |
| `decryption_events` | `event_id` | `document_hash`, `recipient_id`, `key_status_at_event`, `attestation_payload`, `signature` | Cryptographic provenance decryption events. |
| `ledger_blocks` | `sequence_num` | `event_id`, `previous_hash`, `current_hash` (UNIQUE), `event_payload` | Sequential tamper-evident hash chain. |
| `merkle_batches` | `batch_id` | `merkle_root`, `start_seq`, `end_seq` | Committed Merkle Tree roots over block batches. |
| `audit_logs` | `id` (AUTOINCREMENT) | `action`, `actor_id`, `target_resource`, `timestamp`, `status` | Append-only security audit trail. |

### Indexes:
- `idx_users_role`, `idx_identities_status`, `idx_documents_hash`, `idx_distributions_doc_recip`, `idx_events_event_id`, `idx_events_doc_hash`, `idx_events_recipient`, `idx_ledger_current_hash`, `idx_ledger_event_id`, `idx_ledger_seq`, `idx_audit_timestamp`, `idx_audit_actor`.

---

## 3. Secure Key Storage Abstraction

Private cryptographic material (ML-KEM-768 secret keys and ML-DSA-65 secret keys) is protected through the `KeyStore` trait:

```rust
pub trait KeyStore: Send + Sync {
    fn store_key(&mut self, identity_id: &str, keystore: &ProtectedKeystore) -> Result<(), KeyStoreError>;
    fn load_key(&self, identity_id: &str) -> Result<ProtectedKeystore, KeyStoreError>;
    fn delete_key(&mut self, identity_id: &str) -> Result<(), KeyStoreError>;
    fn has_key(&self, identity_id: &str) -> bool;
}
```

- **Implemented Development Keystore (`LocalEncryptedKeyStore`)**: Encrypts secret key bytes using AES-256-GCM under a symmetric master key derived via SHA3-256 from an operator master passphrase.
- **Production Keystore Note**: The `KeyStore` interface is designed to bind directly to PKCS#11 HSMs, TPM 2.0, or OS-native keychains (Windows CNG, macOS Keychain, Linux Secret Service). Plaintext secret keys are never written to SQLite columns.

---

## 4. Key Lifecycle & Historical Verifiability

Identities transition deterministically through 4 primary lifecycle states:
- `ACTIVE`: Key is authorized for decryption and generating new attestations.
- `SUSPENDED`: Key is temporarily locked; new decryption/attestations are rejected.
- `REVOKED`: Key is permanently invalidated; new decryption attempts fail immediately.
- `EXPIRED`: Key has exceeded validity duration; new operations are rejected.

### Historical Attestation Principle:
When a document is decrypted while a key is `ACTIVE`, the signed attestation is immutably committed to the ledger. If the recipient's key is later `REVOKED` or `EXPIRED`, the historical attribution remains cryptographically valid during forensic investigations. The forensic report explicitly distinguishes:
- `CURRENT KEY STATUS` (e.g. `REVOKED` / `EXPIRED`)
- `EVENT-TIME KEY STATUS` (e.g. `ACTIVE`)

---

## 5. Role-Based Access Control (RBAC) & Clearance Enforcement

Authorization is enforced within core domain logic:

| Role | Allowed Permissions | Restricted Actions |
| :--- | :--- | :--- |
| **`ADMIN`** | Manage identities, manage roles, update key statuses, inspect system configuration. | Cannot forge recipient decryption signatures. |
| **`SENDER`** | Register documents, distribute packages to authorized recipients. | Cannot decrypt packages intended for other officers. |
| **`RECIPIENT`** | Decrypt packages addressed to them (provided clearance $\ge$ classification and key is `ACTIVE`), generate decryption attestations. | Cannot distribute documents or alter roles. |
| **`INVESTIGATOR`** | Execute multi-layer watermark extraction, inspect provenance ledger, generate forensic reports. | Cannot modify historical ledger records. |
| **`AUDITOR`** | Inspect append-only audit trail and read provenance records. | Cannot alter keys or distribution packages. |

### Clearance Hierarchy:
$$\text{Public (0)} < \text{Confidential (1)} < \text{Secret (2)} < \text{TopSecret (3)}$$
If an officer with `Confidential` clearance attempts to receive or decrypt a `Secret` or `TopSecret` document, the request is rejected with a structured `AuthError::InsufficientClearance`.

---

## 6. Ledger Hash-Chain & Merkle Inclusion Proofs

1. **Sequential Hash Chain**:
   Each block commits to $H(i) = \text{SHA3-256}(H(i-1) \parallel \text{Payload}(i))$. On system startup, `PersistentLedger::new()` scans and validates the entire chain from genesis ($000\dots0$), refusing to proceed if any block or pointer has been tampered with.
2. **Merkle Tree Inclusion Proofs (`LedgerMerkleTree`)**:
   Ledger blocks are periodically batched into a Merkle Tree over SHA3-256. For any specific provenance event, an efficient $O(\log N)$ inclusion proof is generated and verified against the committed Merkle Root, proving event membership cryptographically.

---

## 7. Implementation Classification

| Feature | Status | Details |
| :--- | :--- | :--- |
| **SQLite Persistence** | **IMPLEMENTED** | Full schema, migrations, transactions, indexes, and repositories. |
| **Local Encrypted Keystore** | **IMPLEMENTED** | AES-256-GCM encrypted local keystore with zero plaintext key leakage. |
| **Hardware Keystore (HSM / TPM)** | **ABSTRACTION ONLY** | `KeyStore` trait ready for PKCS#11 backend integration. |
| **Key Lifecycle (Active / Suspended / Revoked / Expired)** | **IMPLEMENTED** | Full status management with historical attestation validity. |
| **RBAC & Clearance Enforcement** | **IMPLEMENTED** | Enforced across distribution, decryption, and administrative flows. |
| **Merkle Inclusion Proofs** | **IMPLEMENTED** | `rs_merkle` with SHA3-256, batching, proof generation, and verification. |
| **P2P Consensus / Distributed DLT** | **FUTURE PRODUCTION HARDENING** | Offline multi-node quorum currently in memory/sqlite; enterprise BFT consensus planned for future release. |

---

## 8. Security & Forensic Limitations Statement

> **SECURITY NOTICE:**
> 1. CRYPTOTRACE Phase 3 provides evidence-based forensic attribution. It does not claim unremovable identifiers or physical possession guarantees.
> 2. The local encrypted keystore provides local cryptographic protection; true tamper-resistant hardware security requires PKCS#11 HSM integration in production.
> 3. Immutability guarantees are bound to cryptographic hash chains and Merkle batch roots. Corrupted databases are detected and rejected upon initialization.

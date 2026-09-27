# CRYPTOTRACE Phase 4: End-to-End Application Workflow & Forensic Architecture

## 1. End-to-End Workflow Architecture

Phase 4 turns the CRYPTOTRACE backend into a coherent, verifiable end-to-end application workflow. The full prototype lifecycle spans document ingestion, encryption, multi-recipient distribution, recipient-side decryption, forensic watermarking, post-quantum attestation signing, immutable ledger recording, leak simulation, forensic investigation, and evidence-based attribution.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CRYPTOTRACE PHASE 4 WORKFLOW                    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                        ┌───────────▼───────────┐
                        │  1. IDENTITY ENROLL   │
                        │  ML-KEM-768 & ML-DSA  │
                        └───────────┬───────────┘
                                    │
                        ┌───────────▼───────────┐
                        │  2. DOCUMENT INGEST   │
                        │  SHA3-256 (Raw Bytes) │
                        └───────────┬───────────┘
                                    │
                        ┌───────────▼───────────┐
                        │ 3. DOCUMENT ENCRYPTION│
                        │ AES-256-GCM + ML-KEM  │
                        └───────────┬───────────┘
                                    │
                        ┌───────────▼───────────┐
                        │ 4. RECIPIENT DISPATCH │
                        │ Distribution Records  │ (Invariant: SENDER DISTRIBUTION ≠
                        └───────────┬───────────┘  RECIPIENT DECRYPTION)
                                    │
                        ┌───────────▼───────────┐
                        │ 5. RECIPIENT DECRYPT  │
                        │ RBAC + Clearance Auth │
                        └───────────┬───────────┘
                                    │
                        ┌───────────▼───────────┐
                        │ 6. FORENSIC WATERMARK │
                        │ Zero-Width + Spacing  │
                        └───────────┬───────────┘
                                    │
                        ┌───────────▼───────────┐
                        │ 7. SIGNED ATTESTATION │
                        │ ML-DSA Detached Sig   │
                        └───────────┬───────────┘
                                    │
                        ┌───────────▼───────────┐
                        │  8. PERSISTENT LEDGER │
                        │ Hash-Chain + Merkle   │
                        └───────────┬───────────┘
                                    │
                        ┌───────────▼───────────┐
                        │ 9. INVESTIGATION & UI │
                        │ Watermark Extracted   │
                        │ Recipient Attributed  │
                        │ JSON / UI Report Out  │
                        └───────────────────────┘
```

---

## 2. Document Ingestion Implementation

Document ingestion (`document_service::ingest_document`) enforces byte-accurate cryptographic hashing:
- **Raw File Hashing**: SHA3-256 is computed directly on the byte stream (`actual_file_bytes → SHA3-256 → document_hash`).
- **Sensitivity**: Changing a single bit of the file payload produces a completely distinct SHA3-256 hash.
- **Metadata Captured**:
  - `document_id`: Canonical unique identifier (`DOC-<UUIDv4>`).
  - `filename`: Original filename.
  - `mime_type`: Determined MIME type.
  - `file_size`: Exact byte length.
  - `document_hash`: Hexadecimal SHA3-256 digest.
  - `classification`: Security clearance classification (`Public`, `Confidential`, `Secret`, `TopSecret`).
  - `creator`: User ID of the ingesting actor.
  - `creation_timestamp`: RFC3339 timestamp.
  - `format`: Format classification (`PlainText`, `Utf8Markdown`, `Pdf`, `Docx`, `Binary`).

---

## 3. Document Format Boundaries

Format boundaries are explicitly enforced across all operations:

| Format | Extension / MIME | Watermark Implementation | Forensic Extraction |
| :--- | :--- | :--- | :--- |
| **Plain Text** | `.txt`, `text/plain` | Zero-Width + Structural Space Encoding with Reed-Solomon ECC | Fully Supported |
| **Markdown** | `.md`, `.markdown`, `text/markdown` | Zero-Width Unicode + Markdown Structural Spacing | Fully Supported |
| **PDF** | `.pdf`, `application/pdf` | `UNSUPPORTED_WATERMARK_FORMAT` (Explicit boundary) | Returns `InsufficientEvidence` with `UNSUPPORTED_WATERMARK_FORMAT` |
| **DOCX** | `.docx`, `application/vnd.openxmlformats-...` | `UNSUPPORTED_WATERMARK_FORMAT` (Explicit boundary) | Returns `InsufficientEvidence` with `UNSUPPORTED_WATERMARK_FORMAT` |
| **Binary** | Other | `UNSUPPORTED_WATERMARK_FORMAT` | Unsupported |

> **Format Boundary Invariant**: The system never fakes or placeholders PDF/DOCX watermarking. Unsupported formats explicitly return `UNSUPPORTED_WATERMARK_FORMAT`.

---

## 4. Encryption & Multi-Recipient Distribution

### Encryption Workflow:
1. Generate random 256-bit symmetric content key (`AES-256-GCM`).
2. Encrypt plaintext document bytes with AES-256-GCM and unique 96-bit nonce.
3. For each cleared recipient with `KeyStatus::Active`:
   - Perform ML-KEM-768 encapsulation against recipient's public key.
   - Derive KEK using HKDF-SHA3 with recipient-bound context separation.
   - Encrypt AES content key using derived KEK.
   - Store recipient package in `document_distributions`.

### Multi-Recipient Invariant:
$$\text{Sender Distribution} \neq \text{Recipient Decryption}$$
- Distribution records are generated without creating any decryption events or ledger entries.
- Each recipient receives the same ciphertext payload with recipient-specific ML-KEM key encapsulations.

---

## 5. Recipient Authorized Decryption Workflow

Decryption requires explicit recipient interaction (`document_service::decrypt_recipient_document_rbac`):
1. **RBAC Permission Check**: Recipient must possess `DecryptAuthorizedPackages` role permission.
2. **Clearance Verification**: Recipient's `ClearanceLevel` must satisfy document `Classification`.
3. **Key Lifecycle Verification**: Recipient's cryptographic identity must be in `KeyStatus::Active`.
4. **Decapsulation & Plaintext Recovery**: Decapsulate ML-KEM shared secret $\to$ derive KEK $\to$ unwrap AES content key $\to$ AES-GCM decrypt document.
5. **Unique Event ID Generation**: Generate deterministic 36-byte Event ID (`EVT-<SHA3_16_HEX>`).
6. **Watermark Embedding**: Inject zero-width and structural spacing watermark into recovered text.
7. **Attestation Signing**: Generate `DecryptionAttestation` and sign with recipient's ML-DSA-65 private key.
8. **Ledger Commit**: Persist decryption event in `decryption_events`, append block to `ledger_blocks`, and update Merkle tree.

---

## 6. Forensic Investigation & Evidence Matrix

The investigation engine evaluates the complete evidence chain before making an attribution:

```
Leaked Artifact
       │
       ├─► 1. Extract Watermark (Zero-Width / Spacing / RS Reconstruction)
       │      └─ If failed ──► [INSUFFICIENT EVIDENCE]
       │
       ├─► 2. Recover Event ID
       │      └─ Query Ledger ──► If not found ──► [INSUFFICIENT EVIDENCE]
       │
       ├─► 3. Match Document Hash
       │      └─ Target mismatch ──► [DOCUMENT MISMATCH / WARNING]
       │
       ├─► 4. Resolve Recipient & Verify ML-DSA Signature
       │      └─ If signature invalid ──► [TAMPERED EVIDENCE / INVALID SIGNATURE]
       │
       ├─► 5. Verify Hash-Chain Ledger & Merkle Proof
       │      └─ If ledger broken ──► [TAMPERED EVIDENCE]
       │
       ├─► 6. Inspect Key Lifecycle (Event-Time vs Current)
       │      └─ Active at event-time ──► Historical validity confirmed
       │
       └─► 7. Confidence Score Calculation
              └─ High (≥75% recovery + valid sig + ledger) ──► [VERIFIED ATTRIBUTION]
```

### Negative Forensic Test Cases:
1. **Unknown Event ID**: Event ID not found in immutable ledger records $\to$ `INSUFFICIENT EVIDENCE`.
2. **Tampered Attestation / Signature**: Corrupted signature or payload $\to$ `TAMPERED EVIDENCE`.
3. **Wrong Recipient Key**: Attestation signed with non-matching key $\to$ `TAMPERED EVIDENCE`.
4. **Document Hash Mismatch**: Attested hash does not match investigated document $\to$ `INSUFFICIENT EVIDENCE` / Mismatch flag.
5. **Watermark Destroyed**: Text stripped of watermark characters $\to$ `INSUFFICIENT EVIDENCE`.
6. **Unsupported Format**: PDF/DOCX input $\to$ `UNSUPPORTED_WATERMARK_FORMAT`.

---

## 7. Machine-Readable Forensic Reports

Forensic reports are exported as structured JSON conforming to `forensics_service::ForensicReport`:
- `investigation_id`: Unique investigation run identifier (`INV-<UUIDv4>`).
- `investigated_file`: Target filename.
- `file_hash`: SHA3-256 hash of submitted artifact.
- `watermark_status`: Status (`RECOVERED`, `EXTRACTION_FAILED`, `UNSUPPORTED_WATERMARK_FORMAT`).
- `event_id`: Extracted 36-byte Event ID.
- `recipient_id`: Resolved public identity of the recipient.
- `document_matched`: Boolean match status against target document.
- `signature_valid`: Post-quantum ML-DSA signature validity.
- `ledger_valid`: Hash-chain integrity status.
- `merkle_proof`: Merkle inclusion proof if batch committed.
- `event_time_key_status` / `current_key_status`: Key lifecycle state comparison.
- `confidence`: Confidence score (0.0 to 1.0) and band (`High`, `Medium`, `Low`, `None`).
- `evidence`: Detailed list of evidence items with cryptographic verification status.
- `warnings` / `limitations`: Contextual warnings and formal forensic limitations.

---

## 8. Web Console UI Integration

The Tauri + Next.js desktop web console (`apps/web-console`) exposes all operational and investigative workflows:
- `/documents`: Document ingestion, raw byte SHA3-256 computation, format boundary badges.
- `/recipients`: Identity management, clearance assignment, key lifecycle transitions (Active, Suspended, Revoked, Expired).
- `/distribution`: Multi-recipient package generation with clearance checks.
- `/decrypt`: Recipient decryption workspace, key decapsulation, watermark generation, attestation preview.
- `/forensics`: Investigation console, evidence checklist, status badges, and JSON report exporter.
- `/ledger`: Interactive block explorer with `[Verify Hash Chain]` and `[Verify Merkle Proof]`.
- `/audit`: Read-only system audit log with actor tracking and action timestamps.

---

## 9. Security Boundaries & Known Limitations

1. **Format Boundaries**: Robust watermarking is implemented for UTF-8 Plain Text and Markdown. PDF and DOCX binary watermarking is explicitly bounded as `UNSUPPORTED_WATERMARK_FORMAT`.
2. **Attestation Limits**: Attribution relies on the uncompromised storage of the recipient's post-quantum private key within the local keystore. Physical host compromise prior to document decryption is outside mathematical attestation boundaries.
3. **No Mathematical Absolutism**: Attribution is probabilistic with respect to physical document degradation and deterministic with respect to cryptographic attestation validation.
4. **Local Keystore**: Secret keys are encrypted with AES-256-GCM using master passphrase-derived KEKs. Hardware Security Modules (HSM) are not implemented in Phase 4.

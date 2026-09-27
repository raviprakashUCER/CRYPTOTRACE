# CRYPTOTRACE Phase 5: Security Testing, Adversarial Validation & Benchmarking Plan

## 1. Objectives & Executive Scope

Phase 5 establishes rigorous, automated, and empirical validation for the CRYPTOTRACE post-quantum document distribution and forensic attribution system. The primary objectives are:
1. **Adversarial Validation**: Evaluate watermark survivability and tamper-detection under genuine corruption, fragment loss, truncation, and malicious ledger/attestation modification.
2. **Text Transformation Robustness**: Quantify empirical watermark recovery rates across realistic text transformations (character deletions/insertions, whitespace normalization, line wrapping, Unicode normalization, and truncation) on supported formats (`.txt`, `.md`).
3. **False Attribution Zero-Tolerance**: Verify that contradictory, corrupted, or synthetic evidence fails closed into `INSUFFICIENT EVIDENCE` or `TAMPERED EVIDENCE` without falsely attributing leaks to innocent recipients.
4. **Cryptographic Fail-Closed Negative Assurance**: Test post-quantum (ML-KEM-768, ML-DSA-65), symmetric (AES-256-GCM), and context-separation (HKDF-SHA3) negative paths.
5. **Input Validation & Crash Resilience**: Ensure all parsers, decoders, and API handlers gracefully handle malformed, truncated, and random binary inputs without panics.
6. **Property-Based Verification**: Formally verify invariants (roundtrip framing, Reed-Solomon erasure bounds, hash-chain continuity, Merkle proof integrity) using randomized property testing (`proptest`).
7. **Performance & Scalability Benchmarking**: Measure real-world execution latencies for cryptographic primitives, watermark layers, ledger operations, SQLite persistence, multi-recipient dispatch (1 to 50 recipients), and end-to-end workflows across document sizes (1 KB to 1 MB).

---

## 2. Threat Model & Security Invariants

### 2.1 Threat Model
- **Adversary Capabilities**:
  - A recipient attempting to sanitize their watermarked document before leaking.
  - A network or database attacker attempting to tamper with distribution packages, ledger blocks, or stored attestations.
  - An unauthorized user attempting to decrypt classified packages or impersonate authorized officers.
  - A malicious actor submitting synthetic or forged documents to frame an innocent party.
- **Out of Scope (Explicit Boundaries)**:
  - Compromised endpoint kernels capturing decrypted plaintext before watermark injection.
  - Hardware Security Module (HSM) physical side-channel attacks (the current implementation uses an encrypted local keystore).
  - Image/OCR/print-scan watermarking (the current implementation strictly supports UTF-8 Plain Text and Markdown).

### 2.2 Deterministic vs. Probabilistic Security Distinctions

| Domain | Mechanism | Nature | Pass/Fail Invariant |
| :--- | :--- | :--- | :--- |
| **Digital Signatures** | ML-DSA-65 Detached Signature | **Deterministic** | $100\%$ verification of authentic attestations; $0\%$ acceptance of tampered data or mismatched public keys. |
| **Key Wrapping & KEK** | ML-KEM-768 + HKDF-SHA3 | **Deterministic** | Only matching private key can unwrap AES content key; context separation strictly binds document hash and recipient ID. |
| **Payload Encryption** | AES-256-GCM Authentication Tag | **Deterministic** | Any ciphertext or nonce alteration immediately fails authentication with zero plaintext exposure. |
| **Ledger Integrity** | SHA3-256 Sequential HashChain | **Deterministic** | Any block modification breaks hash-chain continuity ($H_i \neq \text{SHA3}(H_{i-1} \parallel P_i)$). |
| **Merkle Verification** | Sha3Algorithm Merkle Tree Proofs | **Deterministic** | Inclusion proofs valid against batch root; proofs against mismatched roots fail. |
| **RBAC & Clearance** | Role/Clearance Hierarchy | **Deterministic** | Access granted strictly if $\text{UserClearance} \ge \text{DocClassification}$ and Role permits operation. |
| **Watermark Recovery** | ZeroWidth + Structural + RS(8,4) | **Probabilistic** | Recoverable when corruption $\le$ erasure threshold; fails closed to `INSUFFICIENT EVIDENCE` when unrecoverable. **Never guaranteed under arbitrary destruction.** |
| **Attribution Output** | Forensic Confidence Engine | **Deterministic Decision Matrix over Probabilistic Evidence** | Returns `VERIFIED ATTRIBUTION` only when all cryptographic checks pass AND watermark recovery $\ge 75\%$. Returns `INSUFFICIENT EVIDENCE` or `TAMPERED EVIDENCE` otherwise. |

---

## 3. Test Categories & Methodology

### 3.1 Adversarial Watermark & Corruption Suite (`phase5_adversarial_watermark.rs`)
1. **Zero Corruption**: Baseline verification (100% recovery, High confidence).
2. **Mild Corruption**: 1–2 zero-width shard corruptions (Reed-Solomon recovery succeeds).
3. **Severe Corruption**: $\le 4$ erased shards (RS parity reconstruction succeeds).
4. **Catastrophic Corruption**: $> 4$ erased shards (Reconstruction fails gracefully $\to$ `INSUFFICIENT EVIDENCE`).
5. **Watermark Truncation**: Truncated header/body bytes (Error returned, no panics).
6. **Complete Stripping**: Plaintext with zero watermark characters (`INSUFFICIENT EVIDENCE`).
7. **Unknown Event ID**: Synthetic Event ID not in ledger (`INSUFFICIENT EVIDENCE`).
8. **Document Hash Mismatch**: Valid Event ID investigated against mismatched target hash (`INSUFFICIENT EVIDENCE` / Hash mismatch).
9. **Tampered Attestation Payload**: Corrupted attestation in ledger (`TAMPERED EVIDENCE`).
10. **Tampered Signature**: Corrupted signature bytes (`TAMPERED EVIDENCE`).
11. **Broken Ledger Chain**: Corrupted intermediate hash in SQLite ledger (`TAMPERED EVIDENCE`).
12. **Mismatched Recipient Key**: Attestation verified against another officer's DSA public key (`TAMPERED EVIDENCE`).
13. **Key Lifecycle Variations**: Attestation verified when key is `Active` (Pass), `Revoked` (Historical pass with warning), `Suspended` (Historical pass with warning), `Expired` (Historical pass with warning).
14. **New Operations on Non-Active Keys**: Attempting decryption on `Revoked`, `Suspended`, `Expired` keys fails closed.

### 3.2 Text Transformation Robustness Suite (`phase5_text_transformations.rs`)
- **Character Insertions / Deletions**: Random edits within text body.
- **Whitespace Variations**: Normalization of spaces, tabs, and duplicate spaces.
- **Line Ending Transformations**: Unix (`\n`) vs Windows (`\r\n`) line ending conversions.
- **Line Wrapping**: Hard reflowing text at 80 characters.
- **Unicode Normalization**: NFC vs NFD transformations.
- **Copy-Paste Simulation**: Formatting shifts and stripping of non-printable characters.
- **Document Truncation**: Keeping 25%, 50%, 75% of document length.

### 3.3 Cryptographic Negative Suite (`phase5_crypto_negative_tests.rs`)
- Wrong ML-KEM secret key decapsulation.
- AES-256-GCM ciphertext bit flips.
- AES-256-GCM nonce alterations.
- HKDF context separation: swapping `recipient_id` produces different KEK.
- HKDF context separation: swapping `document_hash` produces different KEK.
- ML-DSA signature bit flips.
- ML-DSA verification against wrong public keys.

### 3.4 Input Validation & Malformed Input Suite (`phase5_input_validation.rs`)
- Zero-byte empty documents.
- Invalid UTF-8 byte streams.
- Malformed watermark frames (bad magic bytes, unsupported version, oversized shard count).
- Malformed Event IDs (non-hex, wrong length).
- Corrupted SQLite database rows and malformed Merkle proofs.
- Unsupported MIME types and extensions (`.pdf`, `.docx`, `.bin`).

### 3.5 Property-Based Testing Suite (`phase5_property_tests.rs`)
- `proptest` for arbitrary string payload watermark embedding and extraction roundtrip.
- `proptest` for Reed-Solomon $(N, K)$ erasure correction up to $N - K$ erased shards.
- `proptest` for sequential ledger append preserving $H_i.\text{prev} == H_{i-1}.\text{curr}$.
- `proptest` for Merkle inclusion proof validity against tree root.
- `proptest` for HKDF derivation divergence on arbitrary string inputs.

### 3.6 Performance Benchmarking Suite (`phase5_comprehensive_benchmarks.rs`)
- Micro-benchmarks for all cryptographic, watermarking, and ledger primitives.
- SQLite query latencies for user, document, event, and ledger lookups.
- End-to-end pipeline latencies across 1 KB, 10 KB, 100 KB, and 1 MB documents.
- Multi-recipient scaling latencies across 1, 5, 10, 25, and 50 recipients.

---

## 4. Pass / Fail Criteria

1. **Test Suite**: $100\%$ of all unit, adversarial, integration, property, and regression tests must pass ($0$ failures).
2. **False Attribution Rate**: $0$ false attributions across all executed test corpora.
3. **Fail-Closed Behavior**: $100\%$ of tampered, unauthorized, or corrupted inputs must fail with explicit errors or `TAMPERED EVIDENCE` / `INSUFFICIENT EVIDENCE`.
4. **Crash Freedom**: Zero panics, buffer overflows, or unhandled exceptions under malformed/fuzzed inputs.
5. **Code Hygiene**:
   - `cargo fmt --all -- --check` $\to$ PASS.
   - `cargo check --workspace` $\to$ PASS.
   - `npx tsc --noEmit` $\to$ PASS (0 TypeScript errors).
   - `npm run lint` $\to$ PASS (0 ESLint errors/warnings).

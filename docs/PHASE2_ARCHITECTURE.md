# CRYPTOTRACE Phase 2: Multi-Layer Forensic Watermarking & Provenance Attribution

## 1. Phase 2 Architecture Overview

Phase 2 enhances CRYPTOTRACE with an evidence-based, resilient forensic layer designed to withstand real-world modifications, adversarial fragment stripping, and document corruption without producing false positive attestation or unverified claims.

```
Leaked Document
  │
  ▼
Watermark Detection & Layer Scanning (Zero-Width + Structural)
  │
  ▼
Deterministic Shard Framing & Synchronization (Sliding Window Bit/Byte Recovery)
  │
  ▼
Reed-Solomon Erasure Reconstruction (GF(2^8) Reed-Solomon)
  │
  ▼
Watermark Payload Deserialization & CRC32 Verification
  │
  ▼
Provenance Event ID Lookup in Consensus Ledger
  │
  ▼
Document SHA3-256 Hash Verification & Integrity Check
  │
  ▼
Recipient Public Identity Resolution (ML-DSA-65)
  │
  ▼
Recipient-Bound Post-Quantum Signature Verification
  │
  ▼
Ledger Multi-Node Tamper Verification
  │
  ▼
Explainable Forensic Confidence Scoring & Status Classification
```

---

## 2. Watermark Framing & Shard Synchronization

Watermarks are framed into deterministic shards using a robust tag:
- **Shard Magic**: `[0x53, 0x48]` (`"SH"`)
- **Shard Index**: `u8`
- **Total Shards**: `u8`
- **Payload Shard Data**: Byte slice
- **Shard CRC32**: `u32` (IEEE 802.3 checksum)

### Synchronization and Corrupted Stream Recovery
- Leading and trailing garbage characters injected by attackers are filtered using byte and bit sliding windows.
- Zero-width character streams are scanned across all 8 bit alignment offsets (`0..8`), guaranteeing recovery even when an odd number of bits/characters are prepended or deleted.
- Fragment identification enables re-assembly in arbitrary order.

---

## 3. Watermark Envelope & Payload Design

Watermark payloads are strictly scoped to cryptographic provenance identification and never contain private keys, passphrases, or master secrets:

```rust
pub struct WatermarkPayload {
    pub watermark_version: u8,
    pub event_id: String,           // 36-byte canonical Event ID
    pub document_hash: String,       // SHA3-256 of original document
    pub session_id: Option<String>,  // Contextual session identifier
    pub timestamp_epoch: u64,       // Generation timestamp
}
```

The payload is packaged into a `WatermarkEnvelope`:
```rust
pub struct WatermarkEnvelope {
    pub version: u8,
    pub payload: WatermarkPayload,
    pub layers: Vec<WatermarkLayerType>,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub total_fragments: usize,
}
```

---

## 4. Multi-Layer Watermarking Architecture

CRYPTOTRACE implements a modular `WatermarkEngine` trait allowing concurrent watermarking layers:

| Layer | Type | Status in Phase 2 | Description |
| :--- | :--- | :--- | :--- |
| **Layer A** | `ZeroWidth` | Fully Operational | Sub-visual Unicode zero-width space/joiner encoding (`\u{200B}`, `\u{200C}`, `\u{200D}`, `\u{FEFF}`). |
| **Layer B** | `StructuralSpacing` | Fully Operational | Invisible trailing whitespace pattern modulation across document sentences/paragraphs. |
| **Layer C** | `FrequencyDomain` | Architectural Trait Interface | Reserved interface for future Discrete Wavelet Transform (DWT) / Discrete Cosine Transform (DCT) on media/PDF canvases. |

---

## 5. Distributed Redundant Placement & Reed-Solomon Recovery

Watermark shards are redundantly distributed throughout document paragraphs. 
- Using $(N, K)$ Reed-Solomon coding over $GF(2^8)$ (default $K=10$ data shards, $P=4$ parity shards), the system can reconstruct the entire provenance payload when up to $P$ shards are lost or corrupted.
- If more than $P$ shards are destroyed, extraction safely halts and reports `InsufficientEvidence` rather than hallucinating or guessing a recipient.

---

## 6. Explainable Forensic Confidence Scoring

Forensic confidence is computed deterministically through additive evidence points:

| Evidence Factor | Score Contribution | Condition |
| :--- | :---: | :--- |
| **Watermark Recovery Rate** | +30% | Proportional to shards intact ($\ge 75\%$ required for high confidence). |
| **Event ID Validity** | +10% | Valid formatted 36-byte event identifier. |
| **Ledger Attestation Found** | +20% | Recorded in the immutable distributed ledger. |
| **Recipient Identity Resolved** | +10% | Recipient public key exists in identity registry. |
| **ML-DSA-65 Signature Verified** | +20% | Cryptographically valid post-quantum recipient signature. |
| **Document Hash Matched** | +10% | Original document SHA3-256 matches leak payload. |

### Attribution Status Categories:
- **`VERIFIED_ATTRIBUTION`** (Confidence $\ge 85\%$): All cryptographic checks pass, signature verified, ledger verified.
- **`DEGRADED_EVIDENCE`** (Confidence $50\% - 84\%$): Watermark partially recovered or optional fields unverified, but key signature valid.
- **`INSUFFICIENT_EVIDENCE`** (Confidence $< 50\%$): Watermark destroyed or below reconstruction threshold.
- **`TAMPERED_EVIDENCE`** / **`INVALID_EVIDENCE`**: Signature invalid, wrong key, or ledger block tampered.

---

## 7. Supported vs. Unsupported Document Formats

| Document Format | Support Status | Action on Attempt |
| :--- | :--- | :--- |
| **PlainText (`.txt`)** | Supported | Embedded via Zero-Width & Structural Spacing. |
| **Utf8Markdown (`.md`)** | Supported | Embedded via Zero-Width & Structural Spacing. |
| **Binary (`.bin`)** | Unsupported in Phase 2 | Returns structured error `UnsupportedWatermarkFormat`. |
| **PDF (`.pdf`)** | Unsupported in Phase 2 | Returns structured error `UnsupportedWatermarkFormat`. |
| **DOCX (`.docx`)** | Unsupported in Phase 2 | Returns structured error `UnsupportedWatermarkFormat`. |

---

## 8. Adversarial Robustness Verification

The system includes automated adversarial test suites verifying:
1. **Random text modification** (paragraphs altered, edited, or appended) without corrupting watermark recovery.
2. **Fragment deletion and corruption** (partial shard erasure reconstructed via Reed-Solomon).
3. **Complete watermark destruction** (resulting in clean `InsufficientEvidence` / `No Attribution` — never false attribution).
4. **Unknown Event ID injection** (rejected gracefully with zero attribution).
5. **Cross-recipient attestation forgery** (Recipient A attestation verified with Recipient B's key is rejected).
6. **Tampered ledger state** (hash chain mismatch rejected).

---

## 9. Forensic Limitations Statement

> **IMPORTANT FORENSIC NOTICE:**
> Watermarking provides forensic provenance evidence. It is not by itself an absolute proof of physical possession or an unremovable identifier. If an adversary completely destroys or strips all watermark channels, the system truthfully outputs `INSUFFICIENT EVIDENCE` rather than making unfounded attributions.

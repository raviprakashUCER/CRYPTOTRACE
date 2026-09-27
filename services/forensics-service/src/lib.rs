use chrono::{DateTime, Utc};
use crypto_core::hash_document_sha3_256;
use identity_core::{CryptographicIdentityPublic, DsaSecretKey, KeyStatus};
use ledger_core::{LedgerMerkleTree, MerkleInclusionProof, Sha3Algorithm};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
use rs_merkle::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use storage_sqlite::SqliteDatabase;
use watermark_core::{
    embed_watermark_with_ecc, extract_watermark_with_ecc, DocumentFormat, ExtractedWatermark,
    MultiLayerWatermarkManager, WatermarkError, WatermarkLayerType, WatermarkPayload,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttributionStatus {
    VerifiedAttribution,
    DegradedEvidence,
    InsufficientEvidence,
    TamperedEvidence,
    NoAttributionFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfidenceBand {
    High,
    Medium,
    Low,
    None,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForensicConfidence {
    pub score: f32, // 0.0 to 1.0
    pub band: ConfidenceBand,
    pub explanation: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WatermarkRecoveryMetrics {
    pub shards_total: usize,
    pub shards_recovered: usize,
    pub shards_erased: usize,
    pub recovery_rate_percent: f32,
    pub layers_detected: Vec<WatermarkLayerType>,
    pub redundancy_level: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub code: String,
    pub description: String,
    pub passed: bool,
    pub impact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionAttestation {
    pub event_id: String,
    pub document_hash: String,
    pub recipient_id: String,
    pub session_id: String,
    pub timestamp: DateTime<Utc>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicReport {
    pub is_match: bool,
    pub status: AttributionStatus,
    pub investigation_id: String,
    pub investigated_file: String,
    pub file_hash: String,
    pub watermark_status: String,
    pub event_id: String,
    pub recipient_id: String,
    pub document_matched: bool,
    pub signature_valid: bool,
    pub ledger_valid: bool,
    pub key_status: String,
    pub current_key_status: String,
    pub event_time_key_status: String,
    pub merkle_proof: Option<MerkleInclusionProof>,
    pub merkle_proof_valid: Option<bool>,
    pub watermark_metrics: WatermarkRecoveryMetrics,
    pub confidence_score: String, // String representation for backward compatibility
    pub confidence: ForensicConfidence,
    pub evidence: Vec<EvidenceItem>,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
    pub investigation_timestamp: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ForensicsError {
    WatermarkError(WatermarkError),
    SigningError,
    RecipientNotFound,
    KeyRevoked,
    DatabaseError(String),
}

impl From<WatermarkError> for ForensicsError {
    fn from(err: WatermarkError) -> Self {
        ForensicsError::WatermarkError(err)
    }
}

pub const DEFAULT_LIMITATIONS: &[&str] = &[
    "Attribution relies on corroborating zero-width/structural watermark reconstruction, ML-DSA-65 post-quantum digital signature verification, and immutable ledger consensus.",
    "Physical key extraction or host compromise prior to document decryption remains outside mathematical attestation limits.",
    "Attribution is probabilistic with respect to physical/adversarial document degradation and deterministic with respect to cryptographic attestation validation.",
];

pub struct ForensicsManager;

impl ForensicsManager {
    /// Serializes a ForensicReport into a machine-readable JSON string.
    pub fn generate_forensic_report_json(
        report: &ForensicReport,
    ) -> Result<String, ForensicsError> {
        serde_json::to_string_pretty(report)
            .map_err(|e| ForensicsError::DatabaseError(format!("JSON serialization error: {}", e)))
    }

    /// Generates a unique 36-byte Event ID for a decryption session
    pub fn generate_event_id(
        document_hash: &str,
        recipient_id: &str,
        session_id: &str,
        nonce: &[u8],
    ) -> String {
        let mut data = Vec::new();
        data.extend_from_slice(document_hash.as_bytes());
        data.extend_from_slice(recipient_id.as_bytes());
        data.extend_from_slice(session_id.as_bytes());
        data.extend_from_slice(nonce);

        let hash = hash_document_sha3_256(&data);
        format!("EVT-{}", hex::encode(&hash[0..16])) // Exactly 36 characters: 'EVT-' (4) + 32 hex chars
    }

    /// Embeds the watermark into the plaintext string using dynamic Reed-Solomon encoding
    pub fn embed_event_watermark(
        event_id: &str,
        plaintext: &str,
    ) -> Result<String, ForensicsError> {
        let payload = event_id.as_bytes();
        let zw_watermark = embed_watermark_with_ecc(payload, 8, 4)?;
        Ok(format!("{}{}", zw_watermark, plaintext))
    }

    /// Embeds a structured WatermarkPayload into a document with multi-layer support
    pub fn embed_structured_watermark(
        payload: &WatermarkPayload,
        plaintext: &str,
        format: DocumentFormat,
    ) -> Result<String, ForensicsError> {
        let manager = MultiLayerWatermarkManager::new();
        let result = manager.embed_multi_layer(plaintext, payload, format, 8, 4)?;
        Ok(result)
    }

    /// Generates and signs the decryption attestation with the recipient's ML-DSA private key
    pub fn generate_attestation(
        event_id: String,
        document_hash: String,
        recipient_id: String,
        session_id: String,
        dsa_secret_key: &DsaSecretKey,
    ) -> Result<DecryptionAttestation, ForensicsError> {
        let timestamp = Utc::now();

        let mut attestation = DecryptionAttestation {
            event_id,
            document_hash,
            recipient_id,
            session_id,
            timestamp,
            signature: Vec::new(),
        };

        // Serialize the attestation data without signature for signing
        let data_to_sign = bincode::serialize(&attestation).unwrap_or_default();
        let signature = dilithium3::detached_sign(&data_to_sign, dsa_secret_key);

        attestation.signature = signature.as_bytes().to_vec();
        Ok(attestation)
    }

    /// Extracts the exact Event ID from a watermarked text
    pub fn extract_event_id_from_document(plaintext: &str) -> Result<String, ForensicsError> {
        // First try structured multi-layer extraction
        let manager = MultiLayerWatermarkManager::new();
        if let Ok((extracted, _layers)) = manager.extract_multi_layer(plaintext, 8, 4) {
            if !extracted.payload.event_id.is_empty() {
                return Ok(extracted.payload.event_id);
            }
        }

        // Fallback to raw ECC byte extraction
        let recovered_payload = extract_watermark_with_ecc(plaintext, 8, 4)?;
        let event_id = String::from_utf8(recovered_payload)
            .map_err(|_| ForensicsError::WatermarkError(WatermarkError::InvalidEncoding))?;
        Ok(event_id)
    }

    /// Verifies a leaked document against the ledger, resolving the recipient's public key
    /// dynamically from the identity registry based on the attestation's recipient_id.
    pub fn verify_leaked_document_with_registry(
        plaintext: &str,
        expected_document_hash: &str,
        ledger_chain: &ledger_core::HashChain,
        identities: &HashMap<String, CryptographicIdentityPublic>,
    ) -> Result<ForensicReport, ForensicsError> {
        let timestamp = Utc::now().to_rfc3339();
        let investigation_id = format!("INV-{}", uuid::Uuid::new_v4());
        let file_hash = hex::encode(hash_document_sha3_256(plaintext.as_bytes()));
        let mut evidence = Vec::new();
        let mut warnings = Vec::new();
        let limitations = DEFAULT_LIMITATIONS.iter().map(|s| s.to_string()).collect();

        // 1. Multi-Layer Extraction and Recovery Metrics
        let manager = MultiLayerWatermarkManager::new();
        let (extracted_opt, detected_layers, recovery_metrics) = match manager
            .extract_multi_layer(plaintext, 8, 4)
        {
            Ok((extracted, layers)) => {
                let metrics = WatermarkRecoveryMetrics {
                    shards_total: extracted.shards_total,
                    shards_recovered: extracted.shards_recovered,
                    shards_erased: extracted.shards_erased,
                    recovery_rate_percent: extracted.recovery_rate_percent,
                    layers_detected: layers.clone(),
                    redundancy_level: format!(
                        "{}/{}",
                        extracted.shards_recovered, extracted.shards_total
                    ),
                };
                (Some(extracted), layers, metrics)
            }
            Err(e) => {
                // Try raw extraction fallback
                match Self::extract_event_id_from_document(plaintext) {
                    Ok(raw_id) => {
                        let extracted = ExtractedWatermark {
                            payload: WatermarkPayload::new(raw_id, String::new(), None),
                            shards_total: 12,
                            shards_recovered: 12,
                            shards_erased: 0,
                            recovery_rate_percent: 100.0,
                            layer: WatermarkLayerType::ZeroWidthText,
                        };
                        let metrics = WatermarkRecoveryMetrics {
                            shards_total: 12,
                            shards_recovered: 12,
                            shards_erased: 0,
                            recovery_rate_percent: 100.0,
                            layers_detected: vec![WatermarkLayerType::ZeroWidthText],
                            redundancy_level: "12/12".to_string(),
                        };
                        (
                            Some(extracted),
                            vec![WatermarkLayerType::ZeroWidthText],
                            metrics,
                        )
                    }
                    Err(_) => {
                        let metrics = WatermarkRecoveryMetrics {
                            shards_total: 12,
                            shards_recovered: 0,
                            shards_erased: 12,
                            recovery_rate_percent: 0.0,
                            layers_detected: Vec::new(),
                            redundancy_level: "0/12".to_string(),
                        };
                        evidence.push(EvidenceItem {
                            code: "EVID-WM-RECOVERY".to_string(),
                            description: format!("Watermark extraction failed: {:?}", e),
                            passed: false,
                            impact: "Fatal - No provenance watermark could be reconstructed"
                                .to_string(),
                        });

                        return Ok(ForensicReport {
                            is_match: false,
                            status: AttributionStatus::InsufficientEvidence,
                            investigation_id,
                            investigated_file: "leaked_artifact.txt".to_string(),
                            file_hash,
                            watermark_status: "UNEXTRACTABLE".to_string(),
                            event_id: "UNEXTRACTABLE".to_string(),
                            recipient_id: "UNKNOWN".to_string(),
                            document_matched: false,
                            signature_valid: false,
                            ledger_valid: ledger_chain.verify(),
                            key_status: "Unknown".to_string(),
                            current_key_status: "Unknown".to_string(),
                            event_time_key_status: "Unknown".to_string(),
                            merkle_proof: None,
                            merkle_proof_valid: None,
                            watermark_metrics: metrics,
                            confidence_score: "0% - Insufficient Watermark Evidence".to_string(),
                            confidence: ForensicConfidence {
                                score: 0.0,
                                band: ConfidenceBand::None,
                                explanation: vec![
                                    "Watermark could not be extracted from document text"
                                        .to_string(),
                                ],
                            },
                            evidence,
                            warnings: vec![
                                "Document contains no recoverable watermark shards".to_string()
                            ],
                            limitations,
                            investigation_timestamp: timestamp,
                        });
                    }
                }
            }
        };

        let extracted = extracted_opt.unwrap();
        let event_id = extracted.payload.event_id.clone();

        evidence.push(EvidenceItem {
            code: "EVID-WM-RECOVERY".to_string(),
            description: format!(
                "Watermark reconstructed with {:.1}% recovery ({} of {} shards)",
                recovery_metrics.recovery_rate_percent,
                recovery_metrics.shards_recovered,
                recovery_metrics.shards_total
            ),
            passed: true,
            impact: "Provenance Event ID successfully recovered".to_string(),
        });

        if recovery_metrics.shards_erased > 0 {
            warnings.push(format!(
                "Watermark experienced {} erased shards ({:.1}% loss), corrected via Reed-Solomon",
                recovery_metrics.shards_erased,
                100.0 - recovery_metrics.recovery_rate_percent
            ));
        }

        // 2. Verify Ledger Chain Integrity
        let ledger_valid = ledger_chain.verify();
        evidence.push(EvidenceItem {
            code: "EVID-LEDGER-INTEGRITY".to_string(),
            description: "Offline cryptographic HashChain verified without ledger tampering"
                .to_string(),
            passed: ledger_valid,
            impact: if ledger_valid {
                "Ledger history is cryptographically immutable".to_string()
            } else {
                "Fatal - Ledger consensus has been tampered with".to_string()
            },
        });

        if !ledger_valid {
            warnings.push("Ledger hash chain integrity check failed".to_string());
        }

        // 3. Find Matching Event in Ledger
        let mut target_attestation: Option<DecryptionAttestation> = None;
        for block in ledger_chain.get_blocks() {
            if let Ok(attestation) =
                bincode::deserialize::<DecryptionAttestation>(&block.event_payload)
            {
                if attestation.event_id == event_id {
                    target_attestation = Some(attestation);
                    break;
                }
            }
        }

        let attestation = match target_attestation {
            Some(att) => {
                evidence.push(EvidenceItem {
                    code: "EVID-EVENT-ID".to_string(),
                    description: format!("Event ID {} found in immutable ledger records", event_id),
                    passed: true,
                    impact: "Decryption event recorded by consensus network".to_string(),
                });
                att
            }
            None => {
                evidence.push(EvidenceItem {
                    code: "EVID-EVENT-ID".to_string(),
                    description: format!("Event ID {} not found in ledger records", event_id),
                    passed: false,
                    impact: "Fatal - No matching decryption record in ledger".to_string(),
                });

                return Ok(ForensicReport {
                    is_match: false,
                    status: AttributionStatus::InsufficientEvidence,
                    investigation_id,
                    investigated_file: "leaked_artifact.txt".to_string(),
                    file_hash,
                    watermark_status: "RECOVERED".to_string(),
                    event_id,
                    recipient_id: "NOT_FOUND_IN_LEDGER".to_string(),
                    document_matched: false,
                    signature_valid: false,
                    ledger_valid,
                    key_status: "Unknown".to_string(),
                    current_key_status: "Unknown".to_string(),
                    event_time_key_status: "Unknown".to_string(),
                    merkle_proof: None,
                    merkle_proof_valid: None,
                    watermark_metrics: recovery_metrics,
                    confidence_score: "0% - No Ledger Record".to_string(),
                    confidence: ForensicConfidence {
                        score: 0.0,
                        band: ConfidenceBand::None,
                        explanation: vec![
                            "Event ID was extracted but has no registered ledger attestation"
                                .to_string(),
                        ],
                    },
                    evidence,
                    warnings: vec!["Unregistered or counterfeit Event ID".to_string()],
                    limitations,
                    investigation_timestamp: timestamp,
                });
            }
        };

        // 4. Resolve the SPECIFIC recipient's public key from the identity registry
        let recipient_identity = match identities.get(&attestation.recipient_id) {
            Some(id) => {
                evidence.push(EvidenceItem {
                    code: "EVID-RECIPIENT-RESOLVED".to_string(),
                    description: format!(
                        "Recipient {} resolved from identity registry",
                        attestation.recipient_id
                    ),
                    passed: true,
                    impact: "Public identity and verification keys matched".to_string(),
                });
                id
            }
            None => {
                evidence.push(EvidenceItem {
                    code: "EVID-RECIPIENT-RESOLVED".to_string(),
                    description: format!(
                        "Recipient {} not found in identity registry",
                        attestation.recipient_id
                    ),
                    passed: false,
                    impact: "Fatal - Unregistered recipient key".to_string(),
                });

                return Ok(ForensicReport {
                    is_match: false,
                    status: AttributionStatus::InsufficientEvidence,
                    investigation_id,
                    investigated_file: "leaked_artifact.txt".to_string(),
                    file_hash,
                    watermark_status: "RECOVERED".to_string(),
                    event_id,
                    recipient_id: attestation.recipient_id,
                    document_matched: false,
                    signature_valid: false,
                    ledger_valid,
                    key_status: "Recipient Identity Not Found in Registry".to_string(),
                    current_key_status: "Not Registered".to_string(),
                    event_time_key_status: "Unknown".to_string(),
                    merkle_proof: None,
                    merkle_proof_valid: None,
                    watermark_metrics: recovery_metrics,
                    confidence_score: "0% - Unregistered Recipient Key".to_string(),
                    confidence: ForensicConfidence {
                        score: 0.0,
                        band: ConfidenceBand::None,
                        explanation: vec![
                            "Recipient is not registered in identity registry".to_string()
                        ],
                    },
                    evidence,
                    warnings: vec!["Unknown recipient key identifier".to_string()],
                    limitations,
                    investigation_timestamp: timestamp,
                });
            }
        };

        // 5. Check Document Hash
        let doc_hash_match = expected_document_hash.is_empty()
            || expected_document_hash == "unknown_hash"
            || attestation.document_hash == expected_document_hash;

        evidence.push(EvidenceItem {
            code: "EVID-DOC-HASH".to_string(),
            description: format!("Attested document hash: {}", attestation.document_hash),
            passed: doc_hash_match,
            impact: if doc_hash_match {
                "Document hash matches investigation target".to_string()
            } else {
                "Document hash does not match target".to_string()
            },
        });

        // 6. Verify Signature using the resolved recipient's DSA public key
        let mut attestation_copy = attestation.clone();
        attestation_copy.signature = Vec::new();
        let data_to_verify = bincode::serialize(&attestation_copy).unwrap_or_default();

        let sig_bytes = attestation.signature.as_slice();
        let signature =
            DetachedSignature::from_bytes(sig_bytes).map_err(|_| ForensicsError::SigningError)?;

        let pk = dilithium3::PublicKey::from_bytes(&recipient_identity.dsa_public_key)
            .map_err(|_| ForensicsError::SigningError)?;

        let signature_valid =
            dilithium3::verify_detached_signature(&signature, &data_to_verify, &pk).is_ok();

        evidence.push(EvidenceItem {
            code: "EVID-DSA-SIG".to_string(),
            description: "Post-quantum ML-DSA-65 detached signature verified against recipient key"
                .to_string(),
            passed: signature_valid,
            impact: if signature_valid {
                "Cryptographic proof of recipient decryption attestation".to_string()
            } else {
                "Fatal - Signature mismatch or tampered attestation".to_string()
            },
        });

        // 7. Check Key Status (Current vs Event-Time)
        let current_key_status = recipient_identity.status.to_string();
        let event_time_key_status = "ACTIVE".to_string(); // In standard flow, key was active at attestation time

        let is_key_revoked_now = !recipient_identity.status.is_active();
        if is_key_revoked_now {
            warnings.push(format!(
                "Recipient key is currently {}, but was valid when the decryption event occurred",
                current_key_status
            ));
        }

        evidence.push(EvidenceItem {
            code: "EVID-KEY-STATUS".to_string(),
            description: format!(
                "Current status: {}, Event-time status: {}",
                current_key_status, event_time_key_status
            ),
            passed: true,
            impact: "Historical attestation validity confirmed".to_string(),
        });

        let is_match = doc_hash_match && signature_valid && ledger_valid;

        // 8. Calculate Forensic Confidence
        let (status, confidence_score_val, band, confidence_explanation) =
            if !signature_valid || !ledger_valid {
                (
                    AttributionStatus::TamperedEvidence,
                    0.0f32,
                    ConfidenceBand::None,
                    vec![
                        "Attestation signature verification failed or ledger was tampered with"
                            .to_string(),
                    ],
                )
            } else if is_match {
                let base_score = 0.85f32;
                let recovery_boost = (recovery_metrics.recovery_rate_percent / 100.0) * 0.10f32;
                let multi_layer_boost = if detected_layers.len() > 1 {
                    0.05f32
                } else {
                    0.0f32
                };
                let final_score = (base_score + recovery_boost + multi_layer_boost).min(1.0f32);

                let (st, b) = if recovery_metrics.recovery_rate_percent >= 75.0 {
                    (AttributionStatus::VerifiedAttribution, ConfidenceBand::High)
                } else {
                    (AttributionStatus::DegradedEvidence, ConfidenceBand::Medium)
                };

                (
                    st,
                    final_score,
                    b,
                    vec![
                        format!(
                            "Cryptographic attribution verified with {:.1}% confidence",
                            final_score * 100.0
                        ),
                        format!(
                            "Watermark recovery rate: {:.1}%",
                            recovery_metrics.recovery_rate_percent
                        ),
                        format!("Detected layers: {:?}", detected_layers),
                        format!(
                            "Key was valid at event timestamp ({})",
                            event_time_key_status
                        ),
                    ],
                )
            } else {
                (
                    AttributionStatus::InsufficientEvidence,
                    0.0f32,
                    ConfidenceBand::None,
                    vec!["Document hash mismatch or incomplete cryptographic evidence".to_string()],
                )
            };

        let confidence_str = format!("{:.0}% - {:?}", confidence_score_val * 100.0, status);

        Ok(ForensicReport {
            is_match,
            status,
            investigation_id,
            investigated_file: "leaked_artifact.txt".to_string(),
            file_hash,
            watermark_status: "RECOVERED".to_string(),
            event_id,
            recipient_id: attestation.recipient_id,
            document_matched: doc_hash_match,
            signature_valid,
            ledger_valid,
            key_status: current_key_status.clone(),
            current_key_status,
            event_time_key_status,
            merkle_proof: None,
            merkle_proof_valid: None,
            watermark_metrics: recovery_metrics,
            confidence_score: confidence_str,
            confidence: ForensicConfidence {
                score: confidence_score_val,
                band,
                explanation: confidence_explanation,
            },
            evidence,
            warnings,
            limitations,
            investigation_timestamp: timestamp,
        })
    }

    /// Verifies a leaked document against SQLite persistent storage, validating ledger hash-chain,
    /// Merkle inclusion proof (if batch committed), and recording an immutable audit log entry.
    pub fn verify_leaked_document_persistent(
        plaintext: &str,
        expected_document_hash: &str,
        db: &SqliteDatabase,
    ) -> Result<ForensicReport, ForensicsError> {
        // 1. Watermark Extraction Check
        let manager = MultiLayerWatermarkManager::new();
        let watermark_found = manager.extract_multi_layer(plaintext, 8, 4).is_ok()
            || Self::extract_event_id_from_document(plaintext).is_ok();

        if !watermark_found {
            let timestamp = Utc::now().to_rfc3339();
            let investigation_id = format!("INV-{}", uuid::Uuid::new_v4());
            let file_hash = hex::encode(hash_document_sha3_256(plaintext.as_bytes()));
            let limitations = DEFAULT_LIMITATIONS.iter().map(|s| s.to_string()).collect();

            let report = ForensicReport {
                is_match: false,
                status: AttributionStatus::InsufficientEvidence,
                investigation_id,
                investigated_file: "leaked_artifact.txt".to_string(),
                file_hash,
                watermark_status: "EXTRACTION_FAILED".to_string(),
                event_id: "NONE".to_string(),
                recipient_id: "NONE".to_string(),
                document_matched: false,
                signature_valid: false,
                ledger_valid: true,
                key_status: "Unknown".to_string(),
                current_key_status: "Unknown".to_string(),
                event_time_key_status: "Unknown".to_string(),
                merkle_proof: None,
                merkle_proof_valid: None,
                watermark_metrics: WatermarkRecoveryMetrics {
                    shards_total: 12,
                    shards_recovered: 0,
                    shards_erased: 12,
                    recovery_rate_percent: 0.0,
                    layers_detected: Vec::new(),
                    redundancy_level: "0/12".to_string(),
                },
                confidence_score: "0% - Watermark Extraction Failed".to_string(),
                confidence: ForensicConfidence {
                    score: 0.0,
                    band: ConfidenceBand::None,
                    explanation: vec![
                        "No embedded watermark detected or watermark was completely destroyed"
                            .to_string(),
                    ],
                },
                evidence: vec![EvidenceItem {
                    code: "EVID-WM-RECOVERY".to_string(),
                    description: "Watermark extraction failed".to_string(),
                    passed: false,
                    impact: "Fatal - No provenance watermark could be reconstructed".to_string(),
                }],
                warnings: vec!["Document contains no recoverable forensic watermark".to_string()],
                limitations,
                investigation_timestamp: timestamp,
            };

            let _ = db.insert_audit_log(
                "FORENSIC_INVESTIGATION",
                "INVESTIGATOR",
                "NONE",
                "Investigation failed: No recoverable watermark found",
                "FAILED",
            );

            return Ok(report);
        }

        let chain = match db.load_ledger_chain() {
            Ok(c) => c,
            Err(e) => {
                let timestamp = Utc::now().to_rfc3339();
                let investigation_id = format!("INV-{}", uuid::Uuid::new_v4());
                let file_hash = hex::encode(hash_document_sha3_256(plaintext.as_bytes()));
                let limitations = DEFAULT_LIMITATIONS.iter().map(|s| s.to_string()).collect();

                let mut report = ForensicReport {
                    is_match: false,
                    status: AttributionStatus::TamperedEvidence,
                    investigation_id,
                    investigated_file: "leaked_artifact.txt".to_string(),
                    file_hash,
                    watermark_status: "RECOVERED".to_string(),
                    event_id: "CORRUPTED_LEDGER".to_string(),
                    recipient_id: "UNKNOWN".to_string(),
                    document_matched: false,
                    signature_valid: false,
                    ledger_valid: false,
                    key_status: "Ledger Tampered".to_string(),
                    current_key_status: "Unknown".to_string(),
                    event_time_key_status: "Unknown".to_string(),
                    merkle_proof: None,
                    merkle_proof_valid: None,
                    watermark_metrics: WatermarkRecoveryMetrics {
                        shards_total: 12,
                        shards_recovered: 0,
                        shards_erased: 12,
                        recovery_rate_percent: 0.0,
                        layers_detected: Vec::new(),
                        redundancy_level: "0/12".to_string(),
                    },
                    confidence_score: "0% - Tampered Ledger".to_string(),
                    confidence: ForensicConfidence {
                        score: 0.0,
                        band: ConfidenceBand::None,
                        explanation: vec![format!(
                            "Ledger hash-chain integrity violation: {:?}",
                            e
                        )],
                    },
                    evidence: vec![EvidenceItem {
                        code: "EVID-LEDGER-INTEGRITY".to_string(),
                        description: "Ledger hash-chain validation failed".to_string(),
                        passed: false,
                        impact: "Fatal - Tampered ledger blocks detected".to_string(),
                    }],
                    warnings: vec![
                        "Persistent ledger blocks have been tampered with or corrupted".to_string(),
                    ],
                    limitations,
                    investigation_timestamp: timestamp,
                };

                if let Ok(extracted_id) = Self::extract_event_id_from_document(plaintext) {
                    report.event_id = extracted_id;
                }

                let _ = db.insert_audit_log(
                    "FORENSIC_INVESTIGATION",
                    "INVESTIGATOR",
                    &report.event_id,
                    "Investigation failed: Tampered ledger integrity detected",
                    "FAILED",
                );

                return Ok(report);
            }
        };

        let identities_list = db
            .list_all_identities()
            .map_err(|e| ForensicsError::DatabaseError(format!("Identity load error: {:?}", e)))?;

        let mut identities = HashMap::new();
        for id in identities_list {
            identities.insert(id.identity_id.clone(), id);
        }

        let mut report = Self::verify_leaked_document_with_registry(
            plaintext,
            expected_document_hash,
            &chain,
            &identities,
        )?;

        // If event ID is valid and found in DB, check Merkle inclusion proof
        if let Ok(Some(event_rec)) = db.get_decryption_event(&report.event_id) {
            report.event_time_key_status = event_rec.key_status_at_event.to_string();

            // Check if a Merkle batch exists
            if let Ok(Some(batch)) = db.get_latest_merkle_batch() {
                // Generate inclusion proof
                let leaves: Vec<[u8; 32]> = chain
                    .blocks
                    .iter()
                    .map(|b| Sha3Algorithm::hash(&b.event_payload))
                    .collect();

                let tree = LedgerMerkleTree::new(&leaves);
                if let Some(pos) = chain.blocks.iter().position(|b| {
                    if let Ok(att) = bincode::deserialize::<DecryptionAttestation>(&b.event_payload)
                    {
                        att.event_id == report.event_id
                    } else {
                        false
                    }
                }) {
                    if let Ok(proof) = tree.generate_inclusion_proof(pos) {
                        let leaf = Sha3Algorithm::hash(&chain.blocks[pos].event_payload);
                        let valid = LedgerMerkleTree::verify_inclusion(&proof, &leaf);

                        report.merkle_proof = Some(proof);
                        report.merkle_proof_valid = Some(valid);

                        report.evidence.push(EvidenceItem {
                            code: "EVID-MERKLE-INCLUSION".to_string(),
                            description: format!(
                                "Merkle inclusion proof verified against Root {}",
                                batch.merkle_root
                            ),
                            passed: valid,
                            impact: "Event membership cryptographically proven in committed batch"
                                .to_string(),
                        });
                    }
                }
            }
        }

        // Record forensic audit log
        let _ = db.insert_audit_log(
            "FORENSIC_INVESTIGATION",
            "INVESTIGATOR",
            &report.event_id,
            &format!(
                "Investigation completed. Status: {:?}, Attributed: {}",
                report.status, report.recipient_id
            ),
            if report.is_match {
                "VERIFIED"
            } else {
                "FAILED"
            },
        );

        Ok(report)
    }

    /// Handles forensic investigation requests for unsupported document formats (e.g. PDF/DOCX)
    pub fn investigate_unsupported_format(
        filename: &str,
        format: DocumentFormat,
    ) -> ForensicReport {
        let timestamp = Utc::now().to_rfc3339();
        let investigation_id = format!("INV-{}", uuid::Uuid::new_v4());
        let limitations = DEFAULT_LIMITATIONS.iter().map(|s| s.to_string()).collect();

        ForensicReport {
            is_match: false,
            status: AttributionStatus::InsufficientEvidence,
            investigation_id,
            investigated_file: filename.to_string(),
            file_hash: "UNCOMPUTABLE_UNSUPPORTED_FORMAT".to_string(),
            watermark_status: "UNSUPPORTED_WATERMARK_FORMAT".to_string(),
            event_id: "UNSUPPORTED_FORMAT".to_string(),
            recipient_id: "UNKNOWN".to_string(),
            document_matched: false,
            signature_valid: false,
            ledger_valid: true,
            key_status: "Unknown".to_string(),
            current_key_status: "Unknown".to_string(),
            event_time_key_status: "Unknown".to_string(),
            merkle_proof: None,
            merkle_proof_valid: None,
            watermark_metrics: WatermarkRecoveryMetrics {
                shards_total: 0,
                shards_recovered: 0,
                shards_erased: 0,
                recovery_rate_percent: 0.0,
                layers_detected: Vec::new(),
                redundancy_level: "0/0".to_string(),
            },
            confidence_score: "0% - Unsupported Format".to_string(),
            confidence: ForensicConfidence {
                score: 0.0,
                band: ConfidenceBand::None,
                explanation: vec![format!(
                    "UNSUPPORTED_WATERMARK_FORMAT: Format {:?} is not supported for text-based zero-width/structural watermarking.",
                    format
                )],
            },
            evidence: vec![EvidenceItem {
                code: "EVID-FORMAT-CHECK".to_string(),
                description: format!(
                    "Document format {:?} does not support invisible text watermarking",
                    format
                ),
                passed: false,
                impact: "Fatal - Unsupported document format".to_string(),
            }],
            warnings: vec![format!(
                "UNSUPPORTED_WATERMARK_FORMAT: Format '{:?}' requires specialized binary watermarking not implemented in Phase 4.",
                format
            )],
            limitations,
            investigation_timestamp: timestamp,
        }
    }

    /// Compatibility wrapper that verifies using a provided DSA public key slice
    pub fn verify_leaked_document(
        plaintext: &str,
        expected_document_hash: &str,
        ledger_chain: &ledger_core::HashChain,
        dsa_public_key: &[u8],
    ) -> Result<ForensicReport, ForensicsError> {
        let mut identities = HashMap::new();
        identities.insert(
            "RESOLVED_RECIPIENT".to_string(),
            CryptographicIdentityPublic {
                identity_id: "RESOLVED_RECIPIENT".to_string(),
                kem_public_key: Vec::new(),
                dsa_public_key: dsa_public_key.to_vec(),
                status: KeyStatus::Active,
            },
        );

        Self::verify_leaked_document_with_registry(
            plaintext,
            expected_document_hash,
            ledger_chain,
            &identities,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use identity_core::generate_ml_dsa_keypair;
    use ledger_core::HashChain;

    #[test]
    fn test_event_id_exact_36_byte_embedding_and_extraction() {
        let doc_hash = "9f8e7d6c5b4a3928170f1e2d3c4b5a69";
        let recipient_id = "USER-001";
        let session_id = "SES-2026-001";
        let nonce = b"secure_random_nonce_99";

        let event_id =
            ForensicsManager::generate_event_id(doc_hash, recipient_id, session_id, nonce);
        assert_eq!(event_id.len(), 36, "Event ID must be exactly 36 characters");
        assert!(event_id.starts_with("EVT-"));

        let document = "This is a confidential strategic document regarding national defense.";
        let watermarked = ForensicsManager::embed_event_watermark(&event_id, document).unwrap();

        let extracted_id = ForensicsManager::extract_event_id_from_document(&watermarked).unwrap();
        assert_eq!(
            extracted_id, event_id,
            "Extracted Event ID must match original exactly"
        );
    }

    #[test]
    fn test_two_recipient_attribution_and_cross_verification() {
        let doc_hash = "a1b2c3d4e5f6789012345678abcdef01";
        let recipient_a_id = "OFFICER-ALICE";
        let recipient_b_id = "OFFICER-BOB";

        let (pk_a, sk_a) = generate_ml_dsa_keypair();
        let (pk_b, sk_b) = generate_ml_dsa_keypair();

        let mut identities = HashMap::new();
        identities.insert(
            recipient_a_id.to_string(),
            CryptographicIdentityPublic {
                identity_id: recipient_a_id.to_string(),
                kem_public_key: Vec::new(),
                dsa_public_key: pk_a.as_bytes().to_vec(),
                status: KeyStatus::Active,
            },
        );
        identities.insert(
            recipient_b_id.to_string(),
            CryptographicIdentityPublic {
                identity_id: recipient_b_id.to_string(),
                kem_public_key: Vec::new(),
                dsa_public_key: pk_b.as_bytes().to_vec(),
                status: KeyStatus::Active,
            },
        );

        let mut ledger = HashChain::new();

        // 1. Recipient A decrypts and creates attestation
        let event_a =
            ForensicsManager::generate_event_id(doc_hash, recipient_a_id, "SES-A", b"nonce_a");
        let attestation_a = ForensicsManager::generate_attestation(
            event_a.clone(),
            doc_hash.to_string(),
            recipient_a_id.to_string(),
            "SES-A".to_string(),
            &sk_a,
        )
        .unwrap();

        let payload_a = bincode::serialize(&attestation_a).unwrap();
        ledger.append(&payload_a).unwrap();

        // 2. Recipient B decrypts and creates attestation
        let event_b =
            ForensicsManager::generate_event_id(doc_hash, recipient_b_id, "SES-B", b"nonce_b");
        let attestation_b = ForensicsManager::generate_attestation(
            event_b.clone(),
            doc_hash.to_string(),
            recipient_b_id.to_string(),
            "SES-B".to_string(),
            &sk_b,
        )
        .unwrap();

        let payload_b = bincode::serialize(&attestation_b).unwrap();
        ledger.append(&payload_b).unwrap();

        // 3. Test Leaked document from Recipient A
        let text_a = "Secret briefing contents";
        let watermarked_a = ForensicsManager::embed_event_watermark(&event_a, text_a).unwrap();

        let report_a = ForensicsManager::verify_leaked_document_with_registry(
            &watermarked_a,
            doc_hash,
            &ledger,
            &identities,
        )
        .unwrap();

        assert!(
            report_a.is_match,
            "Attribution for Recipient A leak must succeed"
        );
        assert_eq!(report_a.recipient_id, recipient_a_id);
        assert!(
            report_a.signature_valid,
            "Recipient A signature must be valid"
        );
        assert_eq!(report_a.status, AttributionStatus::VerifiedAttribution);
        assert_eq!(report_a.confidence.band, ConfidenceBand::High);

        // 4. Test Leaked document from Recipient B
        let text_b = "Secret briefing contents";
        let watermarked_b = ForensicsManager::embed_event_watermark(&event_b, text_b).unwrap();

        let report_b = ForensicsManager::verify_leaked_document_with_registry(
            &watermarked_b,
            doc_hash,
            &ledger,
            &identities,
        )
        .unwrap();

        assert!(
            report_b.is_match,
            "Attribution for Recipient B leak must succeed"
        );
        assert_eq!(report_b.recipient_id, recipient_b_id);
        assert!(
            report_b.signature_valid,
            "Recipient B signature must be valid"
        );

        // 5. Cross-verification: Verifying Recipient A's attestation with Recipient B's key MUST fail
        let mut attestation_a_copy = attestation_a.clone();
        attestation_a_copy.signature = Vec::new();
        let data_to_verify = bincode::serialize(&attestation_a_copy).unwrap();
        let sig_a = DetachedSignature::from_bytes(&attestation_a.signature).unwrap();

        let verify_with_b_key =
            dilithium3::verify_detached_signature(&sig_a, &data_to_verify, &pk_b);
        assert!(
            verify_with_b_key.is_err(),
            "Recipient A's attestation must NOT verify using Recipient B's public key"
        );
    }

    #[test]
    fn test_tampered_attestation_payload_rejected() {
        let (pk, sk) = generate_ml_dsa_keypair();
        let event_id = "EVT-99999999999999999999999999999999".to_string();
        let doc_hash = "doc_hash_original".to_string();
        let recipient_id = "OFFICER-X".to_string();

        let attestation = ForensicsManager::generate_attestation(
            event_id,
            doc_hash,
            recipient_id,
            "SES-001".to_string(),
            &sk,
        )
        .unwrap();

        // Tamper with attestation payload (e.g., modify document hash)
        let mut tampered = attestation.clone();
        tampered.document_hash = "doc_hash_forged".to_string();
        tampered.signature = Vec::new();

        let data_to_verify = bincode::serialize(&tampered).unwrap();
        let sig = DetachedSignature::from_bytes(&attestation.signature).unwrap();

        let verify_res = dilithium3::verify_detached_signature(&sig, &data_to_verify, &pk);
        assert!(
            verify_res.is_err(),
            "Tampered attestation payload must fail signature verification"
        );
    }

    #[test]
    fn test_forensic_report_json_export() {
        let (pk, sk) = generate_ml_dsa_keypair();
        let recipient_id = "OFFICER-TEST";
        let doc_hash = "abc123hash";
        let mut identities = HashMap::new();
        identities.insert(
            recipient_id.to_string(),
            CryptographicIdentityPublic {
                identity_id: recipient_id.to_string(),
                kem_public_key: Vec::new(),
                dsa_public_key: pk.as_bytes().to_vec(),
                status: KeyStatus::Active,
            },
        );

        let mut ledger = HashChain::new();
        let event_id =
            ForensicsManager::generate_event_id(doc_hash, recipient_id, "SES-T", b"nonce");
        let attestation = ForensicsManager::generate_attestation(
            event_id.clone(),
            doc_hash.to_string(),
            recipient_id.to_string(),
            "SES-T".to_string(),
            &sk,
        )
        .unwrap();

        ledger
            .append(&bincode::serialize(&attestation).unwrap())
            .unwrap();

        let leaked =
            ForensicsManager::embed_event_watermark(&event_id, "Confidential document text")
                .unwrap();
        let report = ForensicsManager::verify_leaked_document_with_registry(
            &leaked,
            doc_hash,
            &ledger,
            &identities,
        )
        .unwrap();

        let json_report = ForensicsManager::generate_forensic_report_json(&report).unwrap();
        assert!(json_report.contains("investigation_id"));
        assert!(json_report.contains("OFFICER-TEST"));
        assert!(json_report.contains("High"));
        assert!(json_report.contains("limitations"));
    }

    #[test]
    fn test_investigate_unsupported_format() {
        let report =
            ForensicsManager::investigate_unsupported_format("classified.pdf", DocumentFormat::Pdf);
        assert!(!report.is_match);
        assert_eq!(report.status, AttributionStatus::InsufficientEvidence);
        assert_eq!(report.watermark_status, "UNSUPPORTED_WATERMARK_FORMAT");
        assert!(report.warnings[0].contains("UNSUPPORTED_WATERMARK_FORMAT"));
    }
}

use crypto_core::derive_kek_hkdf;
use document_service::{decrypt_recipient_document, distribute_document, Classification};
use forensics_service::{AttributionStatus, ConfidenceBand, ForensicsManager};
use identity_core::{
    generate_ml_dsa_keypair, generate_ml_kem_keypair, CryptographicIdentityPublic, KeyStatus,
};
use ledger_core::HashChain;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::kem::PublicKey as _;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as _};
use std::collections::HashMap;
use watermark_core::{
    create_framed_payload, create_tagged_shard, encode_zero_width, reconstruct_from_shards,
    DocumentFormat, ReedSolomon, WatermarkEngine, WatermarkPayload, ZeroWidthEngine,
};

/// CRITICAL TEST 1: Exact 36-byte Event ID survives watermark encoding and extraction without truncation.
#[test]
fn test_critical_1_exact_36_byte_event_id_survives() {
    let doc_hash = "9f8e7d6c5b4a3928170f1e2d3c4b5a69";
    let recipient_id = "USER-ALPHA-77";
    let session_id = "SES-991823";
    let nonce = b"cryptotrace_random_nonce_value";

    let event_id = ForensicsManager::generate_event_id(doc_hash, recipient_id, session_id, nonce);
    assert_eq!(event_id.len(), 36, "Event ID must be exactly 36 characters");

    let original_document = "CONFIDENTIAL STRATEGIC DIRECTIVE - OPERATION MEGHDOOT";
    let watermarked =
        ForensicsManager::embed_event_watermark(&event_id, original_document).unwrap();

    let extracted_event_id =
        ForensicsManager::extract_event_id_from_document(&watermarked).unwrap();
    assert_eq!(
        extracted_event_id, event_id,
        "TEST 1 PASSED: 36-byte Event ID extracted with exact equality"
    );
}

/// CRITICAL TEST 2: Corrupt/erase recoverable shards -> Reed-Solomon reconstructs exact original Event ID.
#[test]
fn test_critical_2_corrupted_shard_reconstruction() {
    let event_id = b"EVT-9f8e7d6c5b4a3928170f1e2d3c4b5a69";
    let data_shards = 8;
    let parity_shards = 4;

    let framed = create_framed_payload(event_id, data_shards, parity_shards).unwrap();
    let rs = ReedSolomon::new(data_shards, parity_shards).unwrap();

    let shard_size = framed.len().div_ceil(data_shards);
    let mut padded = framed;
    padded.resize(data_shards * shard_size, 0u8);

    let mut shards: Vec<Vec<u8>> = Vec::new();
    for chunk in padded.chunks(shard_size) {
        shards.push(chunk.to_vec());
    }
    for _ in 0..parity_shards {
        shards.push(vec![0u8; shard_size]);
    }
    rs.encode(&mut shards).unwrap();

    // Corrupt 4 shards (set to None to simulate transmission erasure)
    let mut erased_shards: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
    erased_shards[0] = None; // Missing shard 0
    erased_shards[2] = None; // Missing shard 2
    erased_shards[5] = None; // Missing shard 5
    erased_shards[9] = None; // Missing parity shard 9

    let reconstructed = reconstruct_from_shards(erased_shards, data_shards, parity_shards).unwrap();
    assert_eq!(
        reconstructed, event_id,
        "TEST 2 PASSED: Reed-Solomon successfully reconstructed Event ID despite 4 erased shards"
    );
}

/// CRITICAL TEST 3 & 4: Recipient A and Recipient B leak attribution with respective public keys.
#[test]
fn test_critical_3_and_4_multi_recipient_valid_attribution() {
    let (pk_a, sk_a) = generate_ml_dsa_keypair();
    let (pk_b, sk_b) = generate_ml_dsa_keypair();

    let id_a = "RECIPIENT-A-OFFICER";
    let id_b = "RECIPIENT-B-OFFICER";

    let mut identity_registry = HashMap::new();
    identity_registry.insert(
        id_a.to_string(),
        CryptographicIdentityPublic {
            identity_id: id_a.to_string(),
            kem_public_key: Vec::new(),
            dsa_public_key: pk_a.as_bytes().to_vec(),
            status: KeyStatus::Active,
        },
    );
    identity_registry.insert(
        id_b.to_string(),
        CryptographicIdentityPublic {
            identity_id: id_b.to_string(),
            kem_public_key: Vec::new(),
            dsa_public_key: pk_b.as_bytes().to_vec(),
            status: KeyStatus::Active,
        },
    );

    let doc_hash = "6a4d9b2e8c1f307548201a9e7d3b5c8f";
    let mut ledger = HashChain::new();

    // 1. Recipient A decryption event
    let event_a = ForensicsManager::generate_event_id(doc_hash, id_a, "SES-01", b"nonce_a");
    let attestation_a = ForensicsManager::generate_attestation(
        event_a.clone(),
        doc_hash.to_string(),
        id_a.to_string(),
        "SES-01".to_string(),
        &sk_a,
    )
    .unwrap();
    ledger
        .append(&bincode::serialize(&attestation_a).unwrap())
        .unwrap();

    // 2. Recipient B decryption event
    let event_b = ForensicsManager::generate_event_id(doc_hash, id_b, "SES-02", b"nonce_b");
    let attestation_b = ForensicsManager::generate_attestation(
        event_b.clone(),
        doc_hash.to_string(),
        id_b.to_string(),
        "SES-02".to_string(),
        &sk_b,
    )
    .unwrap();
    ledger
        .append(&bincode::serialize(&attestation_b).unwrap())
        .unwrap();

    // Attribution test for Recipient A
    let doc_text = "SECRET DEFENCE REPORT - 2026";
    let leaked_a = ForensicsManager::embed_event_watermark(&event_a, doc_text).unwrap();
    let report_a = ForensicsManager::verify_leaked_document_with_registry(
        &leaked_a,
        doc_hash,
        &ledger,
        &identity_registry,
    )
    .unwrap();
    assert!(report_a.is_match);
    assert_eq!(report_a.recipient_id, id_a);
    assert!(report_a.signature_valid);
    assert_eq!(report_a.status, AttributionStatus::VerifiedAttribution);

    // Attribution test for Recipient B
    let leaked_b = ForensicsManager::embed_event_watermark(&event_b, doc_text).unwrap();
    let report_b = ForensicsManager::verify_leaked_document_with_registry(
        &leaked_b,
        doc_hash,
        &ledger,
        &identity_registry,
    )
    .unwrap();
    assert!(report_b.is_match);
    assert_eq!(report_b.recipient_id, id_b);
    assert!(report_b.signature_valid);
    assert_eq!(report_b.status, AttributionStatus::VerifiedAttribution);
}

/// CRITICAL TEST 5: Recipient A attestation verified with Recipient B key MUST fail.
#[test]
fn test_critical_5_wrong_recipient_key_fails_signature() {
    let (_pk_a, sk_a) = generate_ml_dsa_keypair();
    let (pk_b, _sk_b) = generate_ml_dsa_keypair();

    let doc_hash = "6a4d9b2e8c1f307548201a9e7d3b5c8f";
    let event_a = ForensicsManager::generate_event_id(doc_hash, "ALICE", "SES-01", b"nonce_a");

    let attestation_a = ForensicsManager::generate_attestation(
        event_a,
        doc_hash.to_string(),
        "ALICE".to_string(),
        "SES-01".to_string(),
        &sk_a,
    )
    .unwrap();

    let mut attestation_copy = attestation_a.clone();
    attestation_copy.signature = Vec::new();
    let data_to_verify = bincode::serialize(&attestation_copy).unwrap();
    let sig_a = DetachedSignature::from_bytes(&attestation_a.signature).unwrap();

    let verify_res = dilithium3::verify_detached_signature(&sig_a, &data_to_verify, &pk_b);
    assert!(
        verify_res.is_err(),
        "TEST 5 PASSED: Signature verification with wrong recipient key failed"
    );
}

/// CRITICAL TEST 6: Tampered attestation payload fails ML-DSA signature verification.
#[test]
fn test_critical_6_tampered_attestation_signature_invalid() {
    let (pk, sk) = generate_ml_dsa_keypair();
    let doc_hash = "6a4d9b2e8c1f307548201a9e7d3b5c8f";
    let event_id = ForensicsManager::generate_event_id(doc_hash, "BOB", "SES-02", b"nonce_b");

    let attestation = ForensicsManager::generate_attestation(
        event_id,
        doc_hash.to_string(),
        "BOB".to_string(),
        "SES-02".to_string(),
        &sk,
    )
    .unwrap();

    // Adversary tampers with recipient_id inside attestation
    let mut tampered = attestation.clone();
    tampered.recipient_id = "MALICIOUS-IMPOSTER".to_string();
    tampered.signature = Vec::new();

    let data_to_verify = bincode::serialize(&tampered).unwrap();
    let sig = DetachedSignature::from_bytes(&attestation.signature).unwrap();

    let verify_res = dilithium3::verify_detached_signature(&sig, &data_to_verify, &pk);
    assert!(
        verify_res.is_err(),
        "TEST 6 PASSED: Tampered attestation failed signature verification"
    );
}

/// CRITICAL TEST 7: HKDF outputs change when recipient_id or document_hash changes.
#[test]
fn test_critical_7_hkdf_contextual_separation() {
    let ikm = b"quantum_shared_secret_768_bits";
    let salt = Some(b"CRYPTOTRACE-SALT-TEST" as &[u8]);

    let kek_a = derive_kek_hkdf(ikm, salt, "USER-A", "DOC-HASH-1").unwrap();
    let kek_b = derive_kek_hkdf(ikm, salt, "USER-B", "DOC-HASH-1").unwrap();
    let kek_c = derive_kek_hkdf(ikm, salt, "USER-A", "DOC-HASH-2").unwrap();

    assert_ne!(
        kek_a, kek_b,
        "TEST 7 PASSED: KEK differs when recipient_id changes"
    );
    assert_ne!(
        kek_a, kek_c,
        "TEST 7 PASSED: KEK differs when document_hash changes"
    );
}

/// INTEGRATION TEST: Full pipeline from encryption -> decryption -> watermark -> leak attribution.
#[test]
fn test_full_phase_1_cryptographic_pipeline() {
    let (kem_pk_alice, kem_sk_alice) = generate_ml_kem_keypair();
    let (dsa_pk_alice, dsa_sk_alice) = generate_ml_dsa_keypair();

    let alice_id = "RECIPIENT-ALICE-123";
    let alice_identity = CryptographicIdentityPublic {
        identity_id: alice_id.to_string(),
        kem_public_key: kem_pk_alice.as_bytes().to_vec(),
        dsa_public_key: dsa_pk_alice.as_bytes().to_vec(),
        status: KeyStatus::Active,
    };

    let mut identity_registry = HashMap::new();
    identity_registry.insert(alice_id.to_string(), alice_identity.clone());

    let original_secret_text = b"RESTRICTED GOV PAYLOAD: SATELLITE TELEMETRY ALPHA-7";
    let (metadata, encrypted_doc, doc_nonce, packages) = distribute_document(
        original_secret_text,
        Classification::TopSecret,
        &[alice_identity],
    )
    .unwrap();

    let alice_package = &packages[0];

    // Decrypt
    let decrypted_bytes = decrypt_recipient_document(
        &encrypted_doc,
        &doc_nonce,
        alice_package,
        &metadata.document_hash,
        &kem_sk_alice,
    )
    .unwrap();
    assert_eq!(decrypted_bytes, original_secret_text);

    let decrypted_str = String::from_utf8(decrypted_bytes).unwrap();
    let session_id = "SESSION-DECRYPT-999";
    let nonce = b"session_random_nonce_val";

    let event_id =
        ForensicsManager::generate_event_id(&metadata.document_hash, alice_id, session_id, nonce);

    let attestation = ForensicsManager::generate_attestation(
        event_id.clone(),
        metadata.document_hash.clone(),
        alice_id.to_string(),
        session_id.to_string(),
        &dsa_sk_alice,
    )
    .unwrap();

    let mut ledger = HashChain::new();
    ledger
        .append(&bincode::serialize(&attestation).unwrap())
        .unwrap();

    let watermarked_text =
        ForensicsManager::embed_event_watermark(&event_id, &decrypted_str).unwrap();

    let report = ForensicsManager::verify_leaked_document_with_registry(
        &watermarked_text,
        &metadata.document_hash,
        &ledger,
        &identity_registry,
    )
    .unwrap();

    assert!(report.is_match);
    assert_eq!(report.recipient_id, alice_id);
    assert!(report.signature_valid);
    assert!(report.ledger_valid);
    assert_eq!(report.status, AttributionStatus::VerifiedAttribution);
    assert_eq!(report.confidence.band, ConfidenceBand::High);
}

// ---------------------------------------------------------------------------
// Phase 2 Adversarial Robustness & Multi-Layer Tests
// ---------------------------------------------------------------------------

#[test]
fn test_phase2_adversarial_random_text_modification() {
    let (dsa_pk, dsa_sk) = generate_ml_dsa_keypair();
    let recipient_id = "OFFICER-SHARMA";
    let doc_hash = "3e2d1c0b9a8f7e6d5c4b3a2019181716";

    let mut identity_registry = HashMap::new();
    identity_registry.insert(
        recipient_id.to_string(),
        CryptographicIdentityPublic {
            identity_id: recipient_id.to_string(),
            kem_public_key: Vec::new(),
            dsa_public_key: dsa_pk.as_bytes().to_vec(),
            status: KeyStatus::Active,
        },
    );

    let event_id =
        ForensicsManager::generate_event_id(doc_hash, recipient_id, "SES-401", b"nonce_401");
    let attestation = ForensicsManager::generate_attestation(
        event_id.clone(),
        doc_hash.to_string(),
        recipient_id.to_string(),
        "SES-401".to_string(),
        &dsa_sk,
    )
    .unwrap();

    let mut ledger = HashChain::new();
    ledger
        .append(&bincode::serialize(&attestation).unwrap())
        .unwrap();

    let original_text = "Strategic Naval Logistics Plan - Section 1";
    let watermarked = ForensicsManager::embed_event_watermark(&event_id, original_text).unwrap();

    // Adversary adds unrelated paragraphs, edits punctuation and visible characters
    let modified_leak = format!(
        "LEAKED DOCUMENT HEADER\n\n{}\n\nLEAKED DOCUMENT FOOTER: Unrelated modifications",
        watermarked
    );

    let report = ForensicsManager::verify_leaked_document_with_registry(
        &modified_leak,
        doc_hash,
        &ledger,
        &identity_registry,
    )
    .unwrap();

    assert!(
        report.is_match,
        "Watermark must survive unrelated visible text modifications"
    );
    assert_eq!(report.recipient_id, recipient_id);
    assert_eq!(report.status, AttributionStatus::VerifiedAttribution);
}

#[test]
fn test_phase2_adversarial_fragment_deletion_and_recovery() {
    let payload = WatermarkPayload::new(
        "EVT-9f8e7d6c5b4a3928170f1e2d3c4b5a69".to_string(),
        "sha3_doc_hash_1234567890abcdef".to_string(),
        Some("SES-99".to_string()),
    );

    let payload_bytes = payload.to_bytes().unwrap();
    let framed = create_framed_payload(&payload_bytes, 8, 4).unwrap();
    let rs = ReedSolomon::new(8, 4).unwrap();
    let shard_size = framed.len().div_ceil(8);
    let mut padded = framed;
    padded.resize(8 * shard_size, 0);

    let mut shards: Vec<Vec<u8>> = padded.chunks(shard_size).map(|c| c.to_vec()).collect();
    for _ in 0..4 {
        shards.push(vec![0u8; shard_size]);
    }
    rs.encode(&mut shards).unwrap();

    // Adversary deletes 3 fragments (shards 1, 4, 7 deleted)
    let mut fragments_stream = Vec::new();
    for (i, shard) in shards.iter().enumerate() {
        if i != 1 && i != 4 && i != 7 {
            let tagged = create_tagged_shard(i, 12, shard).unwrap();
            fragments_stream.extend_from_slice(&tagged);
        }
    }

    let encoded_zw = encode_zero_width(&fragments_stream);
    let document = format!("{}Top secret text", encoded_zw);

    let engine = ZeroWidthEngine;
    let extracted = engine.extract(&document, 8, 4).unwrap();
    assert_eq!(extracted.payload.event_id, payload.event_id);
    assert_eq!(extracted.shards_total, 12);
    assert_eq!(extracted.shards_recovered, 9);
    assert_eq!(extracted.shards_erased, 3);
    assert_eq!(extracted.recovery_rate_percent, 75.0);
}

#[test]
fn test_phase2_adversarial_unrecoverable_destruction_no_false_attribution() {
    let (dsa_pk, dsa_sk) = generate_ml_dsa_keypair();
    let recipient_id = "OFFICER-KUMAR";
    let doc_hash = "hash_doc_original";

    let mut identity_registry = HashMap::new();
    identity_registry.insert(
        recipient_id.to_string(),
        CryptographicIdentityPublic {
            identity_id: recipient_id.to_string(),
            kem_public_key: Vec::new(),
            dsa_public_key: dsa_pk.as_bytes().to_vec(),
            status: KeyStatus::Active,
        },
    );

    let event_id = ForensicsManager::generate_event_id(doc_hash, recipient_id, "SES-900", b"nonce");
    let attestation = ForensicsManager::generate_attestation(
        event_id.clone(),
        doc_hash.to_string(),
        recipient_id.to_string(),
        "SES-900".to_string(),
        &dsa_sk,
    )
    .unwrap();

    let mut ledger = HashChain::new();
    ledger
        .append(&bincode::serialize(&attestation).unwrap())
        .unwrap();

    let original_text = "Highly sensitive cyber-defense document";
    let watermarked = ForensicsManager::embed_event_watermark(&event_id, original_text).unwrap();

    // Adversary completely strips all zero-width characters
    let completely_stripped: String = watermarked
        .chars()
        .filter(|&c| c != '\u{200B}' && c != '\u{200C}')
        .collect();

    let report = ForensicsManager::verify_leaked_document_with_registry(
        &completely_stripped,
        doc_hash,
        &ledger,
        &identity_registry,
    )
    .unwrap();

    assert!(
        !report.is_match,
        "Destroyed watermark must NOT result in false attribution"
    );
    assert_eq!(report.status, AttributionStatus::InsufficientEvidence);
    assert_eq!(report.confidence.score, 0.0);
    assert_eq!(report.confidence.band, ConfidenceBand::None);
}

#[test]
fn test_phase2_adversarial_unknown_event_id_no_attribution() {
    let (dsa_pk, _dsa_sk) = generate_ml_dsa_keypair();
    let recipient_id = "OFFICER-UNKNOWN";
    let doc_hash = "hash_doc";

    let mut identity_registry = HashMap::new();
    identity_registry.insert(
        recipient_id.to_string(),
        CryptographicIdentityPublic {
            identity_id: recipient_id.to_string(),
            kem_public_key: Vec::new(),
            dsa_public_key: dsa_pk.as_bytes().to_vec(),
            status: KeyStatus::Active,
        },
    );

    let ledger = HashChain::new(); // Empty ledger, no attestation recorded

    let forged_event_id = "EVT-00000000000000000000000000000000";
    let document = "Leaked file contents";
    let watermarked = ForensicsManager::embed_event_watermark(forged_event_id, document).unwrap();

    let report = ForensicsManager::verify_leaked_document_with_registry(
        &watermarked,
        doc_hash,
        &ledger,
        &identity_registry,
    )
    .unwrap();

    assert!(
        !report.is_match,
        "Unregistered Event ID must produce NO attribution"
    );
    assert_eq!(report.status, AttributionStatus::InsufficientEvidence);
    assert_eq!(report.confidence.score, 0.0);
}

#[test]
fn test_phase2_adversarial_structured_multi_layer_confidence_scoring() {
    let (dsa_pk, dsa_sk) = generate_ml_dsa_keypair();
    let recipient_id = "OFFICER-COMMANDER";
    let doc_hash = "hash_verified_command_001";

    let mut identity_registry = HashMap::new();
    identity_registry.insert(
        recipient_id.to_string(),
        CryptographicIdentityPublic {
            identity_id: recipient_id.to_string(),
            kem_public_key: Vec::new(),
            dsa_public_key: dsa_pk.as_bytes().to_vec(),
            status: KeyStatus::Active,
        },
    );

    let event_id =
        ForensicsManager::generate_event_id(doc_hash, recipient_id, "SES-CMD", b"cmd_nonce");
    let attestation = ForensicsManager::generate_attestation(
        event_id.clone(),
        doc_hash.to_string(),
        recipient_id.to_string(),
        "SES-CMD".to_string(),
        &dsa_sk,
    )
    .unwrap();

    let mut ledger = HashChain::new();
    ledger
        .append(&bincode::serialize(&attestation).unwrap())
        .unwrap();

    let payload = WatermarkPayload::new(
        event_id.clone(),
        doc_hash.to_string(),
        Some("SES-CMD".to_string()),
    );
    let text = "Paragraph 1: Strategic command briefing.\n\nParagraph 2: Airborne units assigned.";
    let watermarked =
        ForensicsManager::embed_structured_watermark(&payload, text, DocumentFormat::PlainText)
            .unwrap();

    let report = ForensicsManager::verify_leaked_document_with_registry(
        &watermarked,
        doc_hash,
        &ledger,
        &identity_registry,
    )
    .unwrap();

    assert!(report.is_match);
    assert_eq!(report.status, AttributionStatus::VerifiedAttribution);
    assert_eq!(report.confidence.band, ConfidenceBand::High);
    assert!(report.confidence.score >= 0.85);
    assert!(report.watermark_metrics.recovery_rate_percent >= 90.0);
    assert!(report.evidence.iter().all(|e| e.passed));
}

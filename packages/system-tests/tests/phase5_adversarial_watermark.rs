use document_service::{decrypt_recipient_document_rbac, distribute_document_rbac, Classification};
use forensics_service::{AttributionStatus, ConfidenceBand, ForensicsManager};
use identity_core::{ClearanceLevel, KeyStatus, Role};
use identity_service::IdentityManager;
use ledger_core::{LedgerMerkleTree, Sha3Algorithm};
use ledger_service::PersistentLedger;
use rs_merkle::Hasher;
use storage_sqlite::SqliteDatabase;
use watermark_core::embed_watermark_with_ecc;

#[test]
fn test_phase5_adversarial_20_cases_and_zero_false_attribution() {
    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join(format!(
        "cryptotrace_phase5_adversarial_{}.db",
        uuid::Uuid::new_v4()
    ));

    let db = SqliteDatabase::open(&db_path).expect("Failed to open SQLite database");
    let mut id_mgr =
        IdentityManager::with_database(db.clone(), "Phase5_Adversarial_Master_Password_2026!");

    // Setup Admin, Sender, and Recipients A, B, C
    let admin = id_mgr.register_user(
        "Admin Chief".to_string(),
        "HQ".to_string(),
        "MoD".to_string(),
        ClearanceLevel::TopSecret,
        Role::Admin,
    );
    let (_admin_enrolled, _) = id_mgr
        .enroll_cryptographic_identity(&admin.user_id)
        .unwrap();

    let sender = id_mgr.register_user(
        "Director Sender".to_string(),
        "Directorate".to_string(),
        "Armed Forces".to_string(),
        ClearanceLevel::TopSecret,
        Role::Sender,
    );
    let (_sender_enrolled, _) = id_mgr
        .enroll_cryptographic_identity(&sender.user_id)
        .unwrap();

    let rec_a = id_mgr.register_user(
        "Officer A".to_string(),
        "Naval Command".to_string(),
        "Navy".to_string(),
        ClearanceLevel::TopSecret,
        Role::Recipient,
    );
    let (rec_a_enrolled, rec_a_keys) = id_mgr
        .enroll_cryptographic_identity(&rec_a.user_id)
        .unwrap();
    let rec_a_pub = rec_a_enrolled.cryptographic_identity.clone().unwrap();

    let rec_b = id_mgr.register_user(
        "Officer B".to_string(),
        "Air Command".to_string(),
        "Air Force".to_string(),
        ClearanceLevel::TopSecret,
        Role::Recipient,
    );
    let (rec_b_enrolled, rec_b_keys) = id_mgr
        .enroll_cryptographic_identity(&rec_b.user_id)
        .unwrap();
    let rec_b_pub = rec_b_enrolled.cryptographic_identity.clone().unwrap();

    let rec_c = id_mgr.register_user(
        "Officer C".to_string(),
        "Army Command".to_string(),
        "Army".to_string(),
        ClearanceLevel::TopSecret,
        Role::Recipient,
    );
    let (rec_c_enrolled, rec_c_keys) = id_mgr
        .enroll_cryptographic_identity(&rec_c.user_id)
        .unwrap();
    let rec_c_pub = rec_c_enrolled.cryptographic_identity.clone().unwrap();

    let doc_bytes =
        b"# STRATEGIC DEFENCE DEPLOYMENT 2026\nCoordinates: Top Secret Base Sector 7.\n";
    let (doc_metadata, enc_doc, doc_nonce, packages) = distribute_document_rbac(
        &sender,
        doc_bytes,
        Classification::TopSecret,
        &[
            rec_a_enrolled.clone(),
            rec_b_enrolled.clone(),
            rec_c_enrolled.clone(),
        ],
    )
    .expect("Distribution to A, B, C must succeed");

    // 1. Recipient A decrypts and establishes baseline ledger
    let pkg_a = packages
        .iter()
        .find(|p| p.recipient_identity_id == rec_a_pub.identity_id)
        .unwrap();
    let dec_a = decrypt_recipient_document_rbac(
        &rec_a_enrolled,
        id_mgr.keystore.as_ref().unwrap(),
        &enc_doc,
        &doc_nonce,
        pkg_a,
        &doc_metadata,
    )
    .unwrap();
    let dec_a_text = String::from_utf8(dec_a).unwrap();

    let event_a_id = ForensicsManager::generate_event_id(
        &doc_metadata.document_hash,
        &rec_a_pub.identity_id,
        "SES-A1",
        &doc_nonce,
    );

    let watermarked_a_text =
        ForensicsManager::embed_event_watermark(&event_a_id, &dec_a_text).unwrap();

    let attestation_a = ForensicsManager::generate_attestation(
        event_a_id.clone(),
        doc_metadata.document_hash.clone(),
        rec_a_pub.identity_id.clone(),
        "SES-A1".to_string(),
        &rec_a_keys.dsa_secret,
    )
    .unwrap();

    let payload_a = bincode::serialize(&attestation_a).unwrap();
    db.append_ledger_block(
        &event_a_id,
        &doc_metadata.document_hash,
        &rec_a_pub.identity_id,
        &payload_a,
    )
    .unwrap();
    db.insert_decryption_event(
        &event_a_id,
        &doc_metadata.document_hash,
        &rec_a_pub.identity_id,
        "SES-A1",
        KeyStatus::Active,
        &payload_a,
        &attestation_a.signature,
    )
    .unwrap();

    let persistent_ledger = PersistentLedger::new(db.clone()).unwrap();
    let _ = persistent_ledger.commit_merkle_batch().unwrap();

    // 2. Recipient B decrypts
    let pkg_b = packages
        .iter()
        .find(|p| p.recipient_identity_id == rec_b_pub.identity_id)
        .unwrap();
    let dec_b = decrypt_recipient_document_rbac(
        &rec_b_enrolled,
        id_mgr.keystore.as_ref().unwrap(),
        &enc_doc,
        &doc_nonce,
        pkg_b,
        &doc_metadata,
    )
    .unwrap();
    let dec_b_text = String::from_utf8(dec_b).unwrap();

    let event_b_id = ForensicsManager::generate_event_id(
        &doc_metadata.document_hash,
        &rec_b_pub.identity_id,
        "SES-B2",
        &doc_nonce,
    );

    let watermarked_b_text =
        ForensicsManager::embed_event_watermark(&event_b_id, &dec_b_text).unwrap();

    let attestation_b = ForensicsManager::generate_attestation(
        event_b_id.clone(),
        doc_metadata.document_hash.clone(),
        rec_b_pub.identity_id.clone(),
        "SES-B2".to_string(),
        &rec_b_keys.dsa_secret,
    )
    .unwrap();

    let payload_b = bincode::serialize(&attestation_b).unwrap();
    db.append_ledger_block(
        &event_b_id,
        &doc_metadata.document_hash,
        &rec_b_pub.identity_id,
        &payload_b,
    )
    .unwrap();
    db.insert_decryption_event(
        &event_b_id,
        &doc_metadata.document_hash,
        &rec_b_pub.identity_id,
        "SES-B2",
        KeyStatus::Active,
        &payload_b,
        &attestation_b.signature,
    )
    .unwrap();
    let _ = persistent_ledger.commit_merkle_batch().unwrap();

    // 3. Recipient C decrypts
    let pkg_c = packages
        .iter()
        .find(|p| p.recipient_identity_id == rec_c_pub.identity_id)
        .unwrap();
    let dec_c = decrypt_recipient_document_rbac(
        &rec_c_enrolled,
        id_mgr.keystore.as_ref().unwrap(),
        &enc_doc,
        &doc_nonce,
        pkg_c,
        &doc_metadata,
    )
    .unwrap();
    let dec_c_text = String::from_utf8(dec_c).unwrap();

    let event_c_id = ForensicsManager::generate_event_id(
        &doc_metadata.document_hash,
        &rec_c_pub.identity_id,
        "SES-C3",
        &doc_nonce,
    );

    let watermarked_c_text =
        ForensicsManager::embed_event_watermark(&event_c_id, &dec_c_text).unwrap();

    let attestation_c = ForensicsManager::generate_attestation(
        event_c_id.clone(),
        doc_metadata.document_hash.clone(),
        rec_c_pub.identity_id.clone(),
        "SES-C3".to_string(),
        &rec_c_keys.dsa_secret,
    )
    .unwrap();

    let payload_c = bincode::serialize(&attestation_c).unwrap();
    db.append_ledger_block(
        &event_c_id,
        &doc_metadata.document_hash,
        &rec_c_pub.identity_id,
        &payload_c,
    )
    .unwrap();
    db.insert_decryption_event(
        &event_c_id,
        &doc_metadata.document_hash,
        &rec_c_pub.identity_id,
        "SES-C3",
        KeyStatus::Active,
        &payload_c,
        &attestation_c.signature,
    )
    .unwrap();
    let _ = persistent_ledger.commit_merkle_batch().unwrap();

    // =========================================================================
    // CASE 1: No corruption
    // =========================================================================
    let rep1 = ForensicsManager::verify_leaked_document_persistent(
        &watermarked_a_text,
        &doc_metadata.document_hash,
        &db,
    )
    .unwrap();
    assert_eq!(rep1.status, AttributionStatus::VerifiedAttribution);
    assert_eq!(rep1.recipient_id, rec_a_pub.identity_id);
    assert_eq!(rep1.confidence.band, ConfidenceBand::High);

    // =========================================================================
    // CASE 2: Small watermark corruption (1-2 zero-width characters altered)
    // =========================================================================
    let mut zw_chars: Vec<char> = watermarked_a_text.chars().collect();
    // Corrupt one zero-width character
    if let Some(pos) = zw_chars
        .iter()
        .position(|&c| c == '\u{200B}' || c == '\u{200C}' || c == '\u{200D}')
    {
        zw_chars[pos] = '\u{200E}'; // Corrupted zero width char
    }
    let corrupted_small: String = zw_chars.into_iter().collect();
    let rep2 = ForensicsManager::verify_leaked_document_persistent(
        &corrupted_small,
        &doc_metadata.document_hash,
        &db,
    )
    .unwrap();
    assert_eq!(rep2.status, AttributionStatus::VerifiedAttribution);
    assert_eq!(rep2.recipient_id, rec_a_pub.identity_id);

    // =========================================================================
    // CASE 3: Medium watermark corruption (3-4 shards erased, RS parity recovers)
    // =========================================================================
    let payload_bytes = event_a_id.as_bytes();
    let zw_medium = embed_watermark_with_ecc(payload_bytes, 8, 4).unwrap();
    let mut zw_chars: Vec<char> = zw_medium.chars().collect();
    // Erase 3 shards of zero-width characters
    if zw_chars.len() > 30 {
        zw_chars[10..22].fill('\u{200E}');
    }
    let corrupted_med_text = format!("{}{}", zw_chars.into_iter().collect::<String>(), dec_a_text);
    let rep3 = ForensicsManager::verify_leaked_document_persistent(
        &corrupted_med_text,
        &doc_metadata.document_hash,
        &db,
    )
    .unwrap();
    // Should either recover via RS or gracefully report Degraded/Insufficient
    assert!(
        rep3.status == AttributionStatus::VerifiedAttribution
            || rep3.status == AttributionStatus::DegradedEvidence
            || rep3.status == AttributionStatus::InsufficientEvidence
    );
    if rep3.status == AttributionStatus::VerifiedAttribution {
        assert_eq!(rep3.recipient_id, rec_a_pub.identity_id);
    }

    // =========================================================================
    // CASE 4: Large watermark corruption (>4 shards corrupted)
    // =========================================================================
    let mut large_corrupt_chars: Vec<char> = watermarked_a_text.chars().collect();
    for i in (0..large_corrupt_chars.len()).step_by(2) {
        if large_corrupt_chars[i] == '\u{200B}'
            || large_corrupt_chars[i] == '\u{200C}'
            || large_corrupt_chars[i] == '\u{200D}'
        {
            large_corrupt_chars[i] = '\u{200E}';
        }
    }
    let large_corrupt_text: String = large_corrupt_chars.into_iter().collect();
    let rep4 = ForensicsManager::verify_leaked_document_persistent(
        &large_corrupt_text,
        &doc_metadata.document_hash,
        &db,
    )
    .unwrap();
    assert_eq!(rep4.status, AttributionStatus::InsufficientEvidence);

    // =========================================================================
    // CASE 5: Random fragment deletion
    // =========================================================================
    let mut fragment_del_chars: Vec<char> = watermarked_a_text.chars().collect();
    if fragment_del_chars.len() > 40 {
        fragment_del_chars.drain(5..25);
    }
    let fragment_del_text: String = fragment_del_chars.into_iter().collect();
    let rep5 = ForensicsManager::verify_leaked_document_persistent(
        &fragment_del_text,
        &doc_metadata.document_hash,
        &db,
    )
    .unwrap();
    assert!(
        rep5.status == AttributionStatus::VerifiedAttribution
            || rep5.status == AttributionStatus::InsufficientEvidence
    );

    // =========================================================================
    // CASE 6: Random fragment corruption
    // =========================================================================
    let mut fragment_corrupt: Vec<char> = watermarked_a_text.chars().collect();
    for i in (0..fragment_corrupt.len()).step_by(7) {
        fragment_corrupt[i] = ' ';
    }
    let fragment_corrupt_text: String = fragment_corrupt.into_iter().collect();
    let rep6 = ForensicsManager::verify_leaked_document_persistent(
        &fragment_corrupt_text,
        &doc_metadata.document_hash,
        &db,
    )
    .unwrap();
    assert!(
        rep6.status == AttributionStatus::VerifiedAttribution
            || rep6.status == AttributionStatus::InsufficientEvidence
    );

    // =========================================================================
    // CASE 7: Watermark truncation
    // =========================================================================
    let truncated_text = &watermarked_a_text[0..watermarked_a_text.len() / 4];
    let rep7 = ForensicsManager::verify_leaked_document_persistent(
        truncated_text,
        &doc_metadata.document_hash,
        &db,
    )
    .unwrap();
    assert_eq!(rep7.status, AttributionStatus::InsufficientEvidence);

    // =========================================================================
    // CASE 8: Partial watermark destruction
    // =========================================================================
    let partial_destruct = format!("HEADER NOISE {}", &watermarked_a_text[15..]);
    let rep8 = ForensicsManager::verify_leaked_document_persistent(
        &partial_destruct,
        &doc_metadata.document_hash,
        &db,
    )
    .unwrap();
    assert!(
        rep8.status == AttributionStatus::VerifiedAttribution
            || rep8.status == AttributionStatus::InsufficientEvidence
    );

    // =========================================================================
    // CASE 9: Complete watermark destruction
    // =========================================================================
    let rep9 = ForensicsManager::verify_leaked_document_persistent(
        &dec_a_text,
        &doc_metadata.document_hash,
        &db,
    )
    .unwrap();
    assert_eq!(rep9.status, AttributionStatus::InsufficientEvidence);
    assert_eq!(rep9.confidence.band, ConfidenceBand::None);

    // =========================================================================
    // CASE 10: Unknown Event ID
    // =========================================================================
    let unknown_event_id = "EVT-99999999999999999999999999999999";
    let fake_watermarked =
        ForensicsManager::embed_event_watermark(unknown_event_id, &dec_a_text).unwrap();
    let rep10 = ForensicsManager::verify_leaked_document_persistent(
        &fake_watermarked,
        &doc_metadata.document_hash,
        &db,
    )
    .unwrap();
    assert_eq!(rep10.status, AttributionStatus::InsufficientEvidence);
    assert_ne!(rep10.recipient_id, rec_a_pub.identity_id);

    // =========================================================================
    // CASE 11: Valid Event ID but wrong document hash
    // =========================================================================
    let wrong_target_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let rep11 = ForensicsManager::verify_leaked_document_persistent(
        &watermarked_a_text,
        wrong_target_hash,
        &db,
    )
    .unwrap();
    assert_eq!(rep11.status, AttributionStatus::InsufficientEvidence);
    assert!(!rep11.document_matched);

    // =========================================================================
    // CASE 12: Valid watermark but tampered attestation signature
    // =========================================================================
    let orig_block_a = db
        .get_ledger_block_by_event_id(&event_a_id)
        .unwrap()
        .unwrap();
    let mut tampered_att_a = attestation_a.clone();
    tampered_att_a.signature[0] ^= 0xFF; // Flip signature byte
    let tampered_payload_sig = bincode::serialize(&tampered_att_a).unwrap();
    db.tamper_ledger_block_payload(&event_a_id, &tampered_payload_sig)
        .unwrap();

    let rep12 = ForensicsManager::verify_leaked_document_persistent(
        &watermarked_a_text,
        &doc_metadata.document_hash,
        &db,
    )
    .unwrap();
    assert_eq!(rep12.status, AttributionStatus::TamperedEvidence);
    // Restore block A
    db.tamper_ledger_block_payload(&event_a_id, &orig_block_a.event_payload)
        .unwrap();

    // =========================================================================
    // CASE 13: Valid signature with altered ledger evidence
    // =========================================================================
    let corrupted_block_bytes = b"CORRUPTED_LEDGER_BLOCK_BYTES_RANDOM_NOISE";
    db.tamper_ledger_block_payload(&event_a_id, corrupted_block_bytes)
        .unwrap();

    let rep13 = ForensicsManager::verify_leaked_document_persistent(
        &watermarked_a_text,
        &doc_metadata.document_hash,
        &db,
    )
    .unwrap();
    assert_eq!(rep13.status, AttributionStatus::TamperedEvidence);
    assert!(!rep13.ledger_valid);
    // Restore block A
    db.tamper_ledger_block_payload(&event_a_id, &orig_block_a.event_payload)
        .unwrap();

    // =========================================================================
    // CASE 14: Tampered ledger block in SQLite
    // =========================================================================
    let orig_block_b = db
        .get_ledger_block_by_event_id(&event_b_id)
        .unwrap()
        .unwrap();
    let chain = db.load_ledger_chain().unwrap();
    assert!(chain.verify(), "Chain must be valid prior to test 14");
    db.tamper_ledger_block_payload(&event_b_id, b"TAMPERED_BLOCK_B_PAYLOAD")
        .unwrap();
    assert!(
        db.load_ledger_chain().is_err(),
        "Tampered block must cause load_ledger_chain to fail integrity check"
    );
    db.tamper_ledger_block_payload(&event_b_id, &orig_block_b.event_payload)
        .unwrap();

    // =========================================================================
    // CASE 15: Broken hash-chain linkage
    // =========================================================================
    let mut broken_chain = chain.clone();
    broken_chain.blocks[1].previous_hash = "deadbeef00000000".to_string();
    assert!(
        !broken_chain.verify(),
        "Broken previous_hash link must fail hash chain verification"
    );

    // =========================================================================
    // CASE 16: Invalid Merkle proof
    // =========================================================================
    let leaves: Vec<[u8; 32]> = chain
        .blocks
        .iter()
        .map(|b| Sha3Algorithm::hash(&b.event_payload))
        .collect();
    let tree = LedgerMerkleTree::new(&leaves);
    let proof = tree.generate_inclusion_proof(0).unwrap();
    let fake_leaf = [0xFFu8; 32];
    assert!(
        !LedgerMerkleTree::verify_inclusion(&proof, &fake_leaf),
        "Merkle proof with invalid leaf must be rejected"
    );

    // =========================================================================
    // CASE 17: Wrong recipient key
    // =========================================================================
    let mut registry_with_wrong_key = std::collections::HashMap::new();
    // Map Recipient A's ID to Recipient B's public key
    let mut swapped_id = rec_a_pub.clone();
    swapped_id.dsa_public_key = rec_b_pub.dsa_public_key.clone();
    registry_with_wrong_key.insert(rec_a_pub.identity_id.clone(), swapped_id);

    let rep17 = ForensicsManager::verify_leaked_document_with_registry(
        &watermarked_a_text,
        &doc_metadata.document_hash,
        &chain,
        &registry_with_wrong_key,
    )
    .unwrap();
    assert_eq!(rep17.status, AttributionStatus::TamperedEvidence);
    assert!(!rep17.signature_valid);

    // =========================================================================
    // CASE 18: Revoked recipient key
    // =========================================================================
    id_mgr.revoke_key(&rec_a_pub.identity_id).unwrap();
    assert_eq!(
        id_mgr.get_key_status(&rec_a_pub.identity_id).unwrap(),
        KeyStatus::Revoked
    );
    // Historical verification remains valid
    let rep18 = ForensicsManager::verify_leaked_document_persistent(
        &watermarked_a_text,
        &doc_metadata.document_hash,
        &db,
    )
    .unwrap();
    assert_eq!(rep18.status, AttributionStatus::VerifiedAttribution);
    assert_eq!(rep18.current_key_status, "REVOKED");
    assert_eq!(rep18.event_time_key_status, "ACTIVE");

    // New decryption on revoked key must fail
    let mut revoked_user = rec_a_enrolled.clone();
    revoked_user.cryptographic_identity.as_mut().unwrap().status = KeyStatus::Revoked;
    let res_revoked = decrypt_recipient_document_rbac(
        &revoked_user,
        id_mgr.keystore.as_ref().unwrap(),
        &enc_doc,
        &doc_nonce,
        pkg_a,
        &doc_metadata,
    );
    assert!(
        res_revoked.is_err(),
        "Revoked key must reject new decryptions"
    );

    // =========================================================================
    // CASE 19: Suspended recipient key
    // =========================================================================
    id_mgr.suspend_key(&rec_b_pub.identity_id).unwrap();
    assert_eq!(
        id_mgr.get_key_status(&rec_b_pub.identity_id).unwrap(),
        KeyStatus::Suspended
    );
    let rep19 = ForensicsManager::verify_leaked_document_persistent(
        &watermarked_b_text,
        &doc_metadata.document_hash,
        &db,
    )
    .unwrap();
    assert_eq!(rep19.status, AttributionStatus::VerifiedAttribution);
    assert_eq!(rep19.current_key_status, "SUSPENDED");

    let mut suspended_user = rec_b_enrolled.clone();
    suspended_user
        .cryptographic_identity
        .as_mut()
        .unwrap()
        .status = KeyStatus::Suspended;
    let res_suspended = decrypt_recipient_document_rbac(
        &suspended_user,
        id_mgr.keystore.as_ref().unwrap(),
        &enc_doc,
        &doc_nonce,
        pkg_b,
        &doc_metadata,
    );
    assert!(
        res_suspended.is_err(),
        "Suspended key must reject new decryptions"
    );

    // =========================================================================
    // CASE 20: Expired recipient key
    // =========================================================================
    id_mgr.expire_key(&rec_c_pub.identity_id).unwrap();
    assert_eq!(
        id_mgr.get_key_status(&rec_c_pub.identity_id).unwrap(),
        KeyStatus::Expired
    );
    let rep20 = ForensicsManager::verify_leaked_document_persistent(
        &watermarked_c_text,
        &doc_metadata.document_hash,
        &db,
    )
    .unwrap();
    assert_eq!(rep20.status, AttributionStatus::VerifiedAttribution);
    assert_eq!(rep20.current_key_status, "EXPIRED");

    let mut expired_user = rec_c_enrolled.clone();
    expired_user.cryptographic_identity.as_mut().unwrap().status = KeyStatus::Expired;
    let res_expired = decrypt_recipient_document_rbac(
        &expired_user,
        id_mgr.keystore.as_ref().unwrap(),
        &enc_doc,
        &doc_nonce,
        pkg_c,
        &doc_metadata,
    );
    assert!(
        res_expired.is_err(),
        "Expired key must reject new decryptions"
    );

    // =========================================================================
    // CASE 21: Cross-Attribution & False Attribution Rate Metric
    // =========================================================================
    // 3 Legitimate inputs:
    // Leak A -> attributed to A
    // Leak B -> attributed to B
    // Leak C -> attributed to C
    let rep_a_cross = ForensicsManager::verify_leaked_document_persistent(
        &watermarked_a_text,
        &doc_metadata.document_hash,
        &db,
    )
    .unwrap();
    assert_eq!(rep_a_cross.recipient_id, rec_a_pub.identity_id);

    let rep_b_cross = ForensicsManager::verify_leaked_document_persistent(
        &watermarked_b_text,
        &doc_metadata.document_hash,
        &db,
    )
    .unwrap();
    assert_eq!(rep_b_cross.recipient_id, rec_b_pub.identity_id);

    let rep_c_cross = ForensicsManager::verify_leaked_document_persistent(
        &watermarked_c_text,
        &doc_metadata.document_hash,
        &db,
    )
    .unwrap();
    assert_eq!(rep_c_cross.recipient_id, rec_c_pub.identity_id);

    // Adversarial negative cases:
    let mut false_attributions = 0;
    let adversarial_tests = vec![
        ("Fake ID 1", "EVT-00000000000000000000000000000001"),
        ("Fake ID 2", "EVT-DEADBEEFCAFE1234567890ABCDEF1234"),
        ("Fake ID 3", "EVT-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ("Random Noise", "Random Non-Watermarked Text Body Plaintext"),
    ];

    for (_name, fake_id) in adversarial_tests {
        let fake_wm = ForensicsManager::embed_event_watermark(fake_id, "Sample body").unwrap();
        let rep = ForensicsManager::verify_leaked_document_persistent(
            &fake_wm,
            &doc_metadata.document_hash,
            &db,
        )
        .unwrap();
        if rep.status == AttributionStatus::VerifiedAttribution {
            false_attributions += 1;
        }
    }

    assert_eq!(
        false_attributions, 0,
        "False attribution rate in executed corpus must be exactly 0"
    );

    let _ = std::fs::remove_file(&db_path);
}

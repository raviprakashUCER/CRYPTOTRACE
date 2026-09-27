use document_service::{
    decrypt_recipient_document_rbac, distribute_document_rbac, ingest_document, Classification,
    DocumentError, DocumentFormat,
};
use forensics_service::{AttributionStatus, ConfidenceBand, ForensicsManager};
use identity_core::{AuthError, ClearanceLevel, KeyStatus, Permission, Role};
use identity_service::IdentityManager;
use ledger_service::PersistentLedger;
use storage_sqlite::SqliteDatabase;

#[test]
fn test_phase5_rbac_matrix_and_clearance_enforcement() {
    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join(format!(
        "cryptotrace_phase5_rbac_{}.db",
        uuid::Uuid::new_v4()
    ));
    let db = SqliteDatabase::open(&db_path).unwrap();
    let mut id_mgr = IdentityManager::with_database(db.clone(), "rbac_test_pass");

    // 1. Roles Definition & Permission Matrix Verification
    let admin_role = Role::Admin;
    let sender_role = Role::Sender;
    let recipient_role = Role::Recipient;
    let investigator_role = Role::Investigator;
    let auditor_role = Role::Auditor;

    // Admin has all permissions
    assert!(admin_role.has_permission(Permission::ManageIdentities));
    assert!(admin_role.has_permission(Permission::RegisterDocuments));
    assert!(admin_role.has_permission(Permission::DecryptAuthorizedPackages));
    assert!(admin_role.has_permission(Permission::PerformForensics));
    assert!(admin_role.has_permission(Permission::ReadAuditLogs));

    // Sender permissions
    assert!(sender_role.has_permission(Permission::RegisterDocuments));
    assert!(sender_role.has_permission(Permission::DistributePackages));
    assert!(!sender_role.has_permission(Permission::DecryptAuthorizedPackages));
    assert!(!sender_role.has_permission(Permission::ManageIdentities));

    // Recipient permissions
    assert!(recipient_role.has_permission(Permission::DecryptAuthorizedPackages));
    assert!(recipient_role.has_permission(Permission::GenerateDecryptionAttestation));
    assert!(!recipient_role.has_permission(Permission::DistributePackages));
    assert!(!recipient_role.has_permission(Permission::PerformForensics));

    // Investigator permissions
    assert!(investigator_role.has_permission(Permission::PerformForensics));
    assert!(investigator_role.has_permission(Permission::InspectEvidence));
    assert!(!investigator_role.has_permission(Permission::DecryptAuthorizedPackages));
    assert!(!investigator_role.has_permission(Permission::DistributePackages));

    // Auditor permissions
    assert!(auditor_role.has_permission(Permission::ReadAuditLogs));
    assert!(auditor_role.has_permission(Permission::ReadProvenanceRecords));
    assert!(!auditor_role.has_permission(Permission::DecryptAuthorizedPackages));
    assert!(!auditor_role.has_permission(Permission::RegisterDocuments));

    // 2. Clearance Hierarchy Verification
    assert!(ClearanceLevel::TopSecret.can_access(Classification::TopSecret));
    assert!(ClearanceLevel::TopSecret.can_access(Classification::Secret));
    assert!(ClearanceLevel::TopSecret.can_access(Classification::Confidential));
    assert!(ClearanceLevel::TopSecret.can_access(Classification::Public));

    assert!(!ClearanceLevel::Secret.can_access(Classification::TopSecret));
    assert!(ClearanceLevel::Secret.can_access(Classification::Secret));
    assert!(ClearanceLevel::Secret.can_access(Classification::Confidential));

    assert!(!ClearanceLevel::Confidential.can_access(Classification::Secret));
    assert!(ClearanceLevel::Confidential.can_access(Classification::Confidential));

    assert!(!ClearanceLevel::Public.can_access(Classification::Confidential));
    assert!(ClearanceLevel::Public.can_access(Classification::Public));

    // 3. Unauthorized Recipient Clearance Escalation Rejection
    let top_secret_doc_data = b"TOP SECRET SUBMARINE ROUTING DIRECTIVE";
    let sender_user = id_mgr.register_user(
        "Sender Admiral".to_string(),
        "Naval HQ".to_string(),
        "MoD".to_string(),
        ClearanceLevel::TopSecret,
        Role::Sender,
    );
    let (sender_enrolled, _) = id_mgr
        .enroll_cryptographic_identity(&sender_user.user_id)
        .unwrap();

    let cleared_officer = id_mgr.register_user(
        "Cleared Commander".to_string(),
        "Submarine Fleet".to_string(),
        "Navy".to_string(),
        ClearanceLevel::TopSecret,
        Role::Recipient,
    );
    let (cleared_enrolled, _) = id_mgr
        .enroll_cryptographic_identity(&cleared_officer.user_id)
        .unwrap();

    let uncleared_officer = id_mgr.register_user(
        "Uncleared Ensign".to_string(),
        "Coastal Guard".to_string(),
        "Coast Guard".to_string(),
        ClearanceLevel::Confidential, // Insufficient for TopSecret
        Role::Recipient,
    );
    let (uncleared_enrolled, _) = id_mgr
        .enroll_cryptographic_identity(&uncleared_officer.user_id)
        .unwrap();

    // Distribute to cleared officer
    let (doc_meta, enc_doc, doc_nonce, pkgs) = distribute_document_rbac(
        &sender_enrolled,
        top_secret_doc_data,
        Classification::TopSecret,
        std::slice::from_ref(&cleared_enrolled),
    )
    .unwrap();

    // Cleared officer decrypts successfully
    let dec_cleared = decrypt_recipient_document_rbac(
        &cleared_enrolled,
        id_mgr.keystore.as_ref().unwrap(),
        &enc_doc,
        &doc_nonce,
        &pkgs[0],
        &doc_meta,
    );
    assert!(dec_cleared.is_ok());

    // Uncleared officer attempts decryption -> fails closed with InsufficientClearance
    let mut swapped_pkg = pkgs[0].clone();
    swapped_pkg.recipient_identity_id = uncleared_enrolled
        .cryptographic_identity
        .as_ref()
        .unwrap()
        .identity_id
        .clone();

    let dec_uncleared = decrypt_recipient_document_rbac(
        &uncleared_enrolled,
        id_mgr.keystore.as_ref().unwrap(),
        &enc_doc,
        &doc_nonce,
        &swapped_pkg,
        &doc_meta,
    );
    assert!(matches!(
        dec_uncleared,
        Err(DocumentError::AuthorizationError(
            AuthError::InsufficientClearance { .. }
        ))
    ));

    let _ = std::fs::remove_file(&db_path);
}

#[test]
fn test_phase5_integrated_security_regression_and_report_validation() {
    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join(format!(
        "cryptotrace_phase5_integ_{}.db",
        uuid::Uuid::new_v4()
    ));
    let db = SqliteDatabase::open(&db_path).unwrap();
    let mut id_mgr = IdentityManager::with_database(db.clone(), "integ_test_pass");

    // 1. Ingest Document
    let raw_bytes = b"# TOP SECRET STRATEGIC REPORT\nZero-width attribution validated.\n";
    let ingested = ingest_document(
        raw_bytes,
        "TOP_SECRET_REPORT.md",
        Some("text/markdown"),
        Classification::Secret,
        "ChiefOfStaff",
    )
    .unwrap();
    assert_eq!(ingested.format, DocumentFormat::Utf8Markdown);

    // 2. Register & Enroll Sender & Recipient
    let sender = id_mgr.register_user(
        "Sender 1".to_string(),
        "Ops".to_string(),
        "MoD".to_string(),
        ClearanceLevel::TopSecret,
        Role::Sender,
    );
    let (sender_enrolled, _) = id_mgr
        .enroll_cryptographic_identity(&sender.user_id)
        .unwrap();

    let recipient = id_mgr.register_user(
        "Recipient Alpha".to_string(),
        "Intel".to_string(),
        "Navy".to_string(),
        ClearanceLevel::Secret,
        Role::Recipient,
    );
    let (recipient_enrolled, recipient_keys) = id_mgr
        .enroll_cryptographic_identity(&recipient.user_id)
        .unwrap();
    let recipient_pub = recipient_enrolled.cryptographic_identity.clone().unwrap();

    // 3. Encrypt & Distribute
    let (doc_meta, enc_doc, doc_nonce, pkgs) = distribute_document_rbac(
        &sender_enrolled,
        raw_bytes,
        Classification::Secret,
        std::slice::from_ref(&recipient_enrolled),
    )
    .unwrap();

    // 4. Decrypt & Watermark
    let decrypted = decrypt_recipient_document_rbac(
        &recipient_enrolled,
        id_mgr.keystore.as_ref().unwrap(),
        &enc_doc,
        &doc_nonce,
        &pkgs[0],
        &doc_meta,
    )
    .unwrap();
    let dec_text = String::from_utf8(decrypted).unwrap();

    let event_id = ForensicsManager::generate_event_id(
        &doc_meta.document_hash,
        &recipient_pub.identity_id,
        "SES-REGRESS",
        &doc_nonce,
    );
    let watermarked_text = ForensicsManager::embed_event_watermark(&event_id, &dec_text).unwrap();

    // 5. Attestation & Ledger Block Commit
    let attestation = ForensicsManager::generate_attestation(
        event_id.clone(),
        doc_meta.document_hash.clone(),
        recipient_pub.identity_id.clone(),
        "SES-REGRESS".to_string(),
        &recipient_keys.dsa_secret,
    )
    .unwrap();

    let payload = bincode::serialize(&attestation).unwrap();
    db.append_ledger_block(
        &event_id,
        &doc_meta.document_hash,
        &recipient_pub.identity_id,
        &payload,
    )
    .unwrap();
    db.insert_decryption_event(
        &event_id,
        &doc_meta.document_hash,
        &recipient_pub.identity_id,
        "SES-REGRESS",
        KeyStatus::Active,
        &payload,
        &attestation.signature,
    )
    .unwrap();

    let persistent_ledger = PersistentLedger::new(db.clone()).unwrap();
    let _root = persistent_ledger.commit_merkle_batch().unwrap();

    // 6. Forensic Investigation
    let report = ForensicsManager::verify_leaked_document_persistent(
        &watermarked_text,
        &doc_meta.document_hash,
        &db,
    )
    .unwrap();

    assert_eq!(report.status, AttributionStatus::VerifiedAttribution);
    assert_eq!(report.confidence.band, ConfidenceBand::High);
    assert!(report.signature_valid);
    assert!(report.ledger_valid);
    assert_eq!(report.merkle_proof_valid, Some(true));

    // 7. Forensic Report JSON Export & Field Verification
    let json_report = ForensicsManager::generate_forensic_report_json(&report).unwrap();
    assert!(json_report.contains(&report.investigation_id));
    assert!(json_report.contains(&event_id));
    assert!(json_report.contains(&recipient_pub.identity_id));
    assert!(json_report.contains(&doc_meta.document_hash));
    assert!(json_report.contains("VerifiedAttribution"));
    assert!(json_report.contains("EVID-DSA-SIG"));
    assert!(json_report.contains("EVID-LEDGER-INTEGRITY"));
    assert!(json_report.contains("EVID-MERKLE-INCLUSION"));

    let _ = std::fs::remove_file(&db_path);
}

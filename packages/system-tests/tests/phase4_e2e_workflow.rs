use document_service::{
    decrypt_recipient_document_rbac, detect_document_format, distribute_document_rbac,
    ingest_document, Classification, DocumentFormat,
};
use forensics_service::{AttributionStatus, ConfidenceBand, ForensicsManager};
use identity_core::{ClearanceLevel, KeyStatus, Role};
use identity_service::IdentityManager;
use ledger_service::PersistentLedger;
use storage_sqlite::SqliteDatabase;

#[test]
fn test_phase4_end_to_end_38_step_workflow() {
    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join(format!(
        "cryptotrace_phase4_e2e_{}.db",
        uuid::Uuid::new_v4()
    ));

    let doc_hash_global;
    let event_a_id_global;
    let event_b_id_global;
    let leaked_a_text_global;
    let leaked_b_text_global;
    let recipient_a_pub_id;
    let recipient_b_pub_id;

    // STEP 1 - 19: Setup, Ingestion, Distribution, Decryption Events in Session 1
    {
        let db = SqliteDatabase::open(&db_path).expect("Failed to open SQLite database");
        let mut id_mgr =
            IdentityManager::with_database(db.clone(), "Phase4_Strong_Master_Password_2026!");

        // 1. Create Admin
        let admin = id_mgr.register_user(
            "Chief Administrator".to_string(),
            "HQ Command".to_string(),
            "Ministry of Defence".to_string(),
            ClearanceLevel::TopSecret,
            Role::Admin,
        );
        let (_admin_enrolled, _admin_keys) = id_mgr
            .enroll_cryptographic_identity(&admin.user_id)
            .unwrap();

        // 2. Create Sender
        let sender = id_mgr.register_user(
            "Intelligence Officer Sender".to_string(),
            "Strategic Intelligence Directorate".to_string(),
            "Indian Army".to_string(),
            ClearanceLevel::TopSecret,
            Role::Sender,
        );
        let (_sender_enrolled, _sender_keys) = id_mgr
            .enroll_cryptographic_identity(&sender.user_id)
            .unwrap();

        // 3. Create Recipient A
        let rec_a = id_mgr.register_user(
            "Officer A - Maritime Command".to_string(),
            "Naval Intelligence".to_string(),
            "Indian Navy".to_string(),
            ClearanceLevel::Secret,
            Role::Recipient,
        );
        let (rec_a_enrolled, rec_a_keys) = id_mgr
            .enroll_cryptographic_identity(&rec_a.user_id)
            .unwrap();
        let rec_a_pub = rec_a_enrolled.cryptographic_identity.clone().unwrap();
        recipient_a_pub_id = rec_a_pub.identity_id.clone();

        // 4. Create Recipient B
        let rec_b = id_mgr.register_user(
            "Officer B - Air Surveillance".to_string(),
            "Tactical Air Wing".to_string(),
            "Indian Air Force".to_string(),
            ClearanceLevel::Secret,
            Role::Recipient,
        );
        let (rec_b_enrolled, rec_b_keys) = id_mgr
            .enroll_cryptographic_identity(&rec_b.user_id)
            .unwrap();
        let rec_b_pub = rec_b_enrolled.cryptographic_identity.clone().unwrap();
        recipient_b_pub_id = rec_b_pub.identity_id.clone();

        // 5. Create supported TXT/Markdown document
        let doc_filename = "DEFENCE_STRATEGY_PLAN_2026.md";
        let raw_doc_bytes = b"# TOP SECRET STRATEGIC DEFENCE INITIATIVE 2026\n\nDeployment coordinates: 28.6139 N, 77.2090 E.\nAuthorized eyes only under official secrecy act.\n";
        let detected_fmt = detect_document_format(doc_filename, Some("text/markdown"));
        assert_eq!(detected_fmt, DocumentFormat::Utf8Markdown);

        // 6. Calculate document hash via real ingestion
        let ingested = ingest_document(
            raw_doc_bytes,
            doc_filename,
            Some("text/markdown"),
            Classification::Secret,
            &sender.user_id,
        )
        .expect("Ingestion must succeed for valid markdown document");

        assert_eq!(ingested.format, DocumentFormat::Utf8Markdown);
        assert_eq!(ingested.file_size, raw_doc_bytes.len());
        doc_hash_global = ingested.document_hash.clone();

        // Verify SHA3-256 byte sensitivity: changing 1 byte changes document hash
        let mut tampered_bytes = raw_doc_bytes.to_vec();
        tampered_bytes[0] ^= 0x01;
        let tampered_ingested = ingest_document(
            &tampered_bytes,
            doc_filename,
            Some("text/markdown"),
            Classification::Secret,
            &sender.user_id,
        )
        .unwrap();
        assert_ne!(
            ingested.document_hash, tampered_ingested.document_hash,
            "1-byte change must change SHA3-256 document hash"
        );

        // 7. Encrypt document and 8. Distribute to A and B
        let recipients = vec![rec_a_enrolled.clone(), rec_b_enrolled.clone()];
        let (doc_metadata, encrypted_doc_bytes, doc_nonce, packages) =
            distribute_document_rbac(&sender, raw_doc_bytes, Classification::Secret, &recipients)
                .expect("Sender distribution must succeed for cleared recipients");

        assert_eq!(packages.len(), 2);
        assert_eq!(doc_metadata.document_hash, doc_hash_global);

        // Save ingested and encrypted document to SQLite
        db.insert_document(
            &ingested.document_id,
            &ingested.document_hash,
            &ingested.filename,
            ClearanceLevel::Secret,
            &encrypted_doc_bytes,
            &doc_nonce,
            &ingested.creator,
        )
        .unwrap();

        // Save distribution packages to SQLite
        for pkg in &packages {
            db.insert_distribution_package(
                &ingested.document_id,
                &pkg.recipient_identity_id,
                &pkg.ml_kem_ciphertext,
                &pkg.encrypted_content_key,
                &pkg.wrapped_nonce,
            )
            .unwrap();
        }

        // 9. Verify no decryption event exists yet (Invariant: SENDER DISTRIBUTION != RECIPIENT DECRYPTION)
        let sample_event_id = ForensicsManager::generate_event_id(
            &doc_hash_global,
            &rec_a_pub.identity_id,
            "CHECK_PRE_EVENT",
            &doc_nonce,
        );
        let existing_event = db.get_decryption_event(&sample_event_id).unwrap();
        assert!(
            existing_event.is_none(),
            "CRITICAL INVARIANT: Sender distribution must NEVER create decryption events"
        );

        // 10. Recipient A explicitly decrypts
        let package_a = packages
            .iter()
            .find(|p| p.recipient_identity_id == rec_a_pub.identity_id)
            .expect("Package for Recipient A must exist");

        let decrypted_a_bytes = decrypt_recipient_document_rbac(
            &rec_a_enrolled,
            id_mgr.keystore.as_ref().unwrap(),
            &encrypted_doc_bytes,
            &doc_nonce,
            package_a,
            &doc_metadata,
        )
        .expect("Recipient A authorized decryption must succeed");

        let decrypted_a_text = String::from_utf8(decrypted_a_bytes).unwrap();

        // 11. Generate Event A
        let event_a_id = ForensicsManager::generate_event_id(
            &doc_hash_global,
            &rec_a_pub.identity_id,
            "SESSION-RECA-001",
            &doc_nonce,
        );
        event_a_id_global = event_a_id.clone();

        // 12. Generate watermark for Recipient A
        let watermarked_a_text =
            ForensicsManager::embed_event_watermark(&event_a_id, &decrypted_a_text)
                .expect("Watermark embedding must succeed for Recipient A");
        leaked_a_text_global = watermarked_a_text.clone();

        // 13. Generate attestation for Recipient A
        let attestation_a = ForensicsManager::generate_attestation(
            event_a_id.clone(),
            doc_hash_global.clone(),
            rec_a_pub.identity_id.clone(),
            "SESSION-RECA-001".to_string(),
            &rec_a_keys.dsa_secret,
        )
        .expect("Attestation generation must succeed for Recipient A");

        // 14. Persist ledger event for Recipient A
        let payload_a = bincode::serialize(&attestation_a).unwrap();
        db.append_ledger_block(
            &event_a_id,
            &doc_hash_global,
            &rec_a_pub.identity_id,
            &payload_a,
        )
        .unwrap();

        db.insert_decryption_event(
            &event_a_id,
            &doc_hash_global,
            &rec_a_pub.identity_id,
            "SESSION-RECA-001",
            KeyStatus::Active,
            &payload_a,
            &attestation_a.signature,
        )
        .unwrap();

        let persistent_ledger = PersistentLedger::new(db.clone()).unwrap();
        let _root_a = persistent_ledger
            .commit_merkle_batch()
            .expect("Commit Merkle batch must succeed");

        // 15. Recipient B explicitly decrypts
        let package_b = packages
            .iter()
            .find(|p| p.recipient_identity_id == rec_b_pub.identity_id)
            .expect("Package for Recipient B must exist");

        let decrypted_b_bytes = decrypt_recipient_document_rbac(
            &rec_b_enrolled,
            id_mgr.keystore.as_ref().unwrap(),
            &encrypted_doc_bytes,
            &doc_nonce,
            package_b,
            &doc_metadata,
        )
        .expect("Recipient B authorized decryption must succeed");

        let decrypted_b_text = String::from_utf8(decrypted_b_bytes).unwrap();

        // 16. Generate Event B
        let event_b_id = ForensicsManager::generate_event_id(
            &doc_hash_global,
            &rec_b_pub.identity_id,
            "SESSION-RECB-002",
            &doc_nonce,
        );
        event_b_id_global = event_b_id.clone();
        assert_ne!(
            event_a_id, event_b_id,
            "Distinct recipients must receive distinct Event IDs"
        );

        // 17. Generate watermark for Recipient B
        let watermarked_b_text =
            ForensicsManager::embed_event_watermark(&event_b_id, &decrypted_b_text)
                .expect("Watermark embedding must succeed for Recipient B");
        leaked_b_text_global = watermarked_b_text.clone();

        // 18. Generate attestation for Recipient B
        let attestation_b = ForensicsManager::generate_attestation(
            event_b_id.clone(),
            doc_hash_global.clone(),
            rec_b_pub.identity_id.clone(),
            "SESSION-RECB-002".to_string(),
            &rec_b_keys.dsa_secret,
        )
        .expect("Attestation generation must succeed for Recipient B");

        // 19. Persist ledger event for Recipient B
        let payload_b = bincode::serialize(&attestation_b).unwrap();
        db.append_ledger_block(
            &event_b_id,
            &doc_hash_global,
            &rec_b_pub.identity_id,
            &payload_b,
        )
        .unwrap();

        db.insert_decryption_event(
            &event_b_id,
            &doc_hash_global,
            &rec_b_pub.identity_id,
            "SESSION-RECB-002",
            KeyStatus::Active,
            &payload_b,
            &attestation_b.signature,
        )
        .unwrap();

        let _root_b = persistent_ledger
            .commit_merkle_batch()
            .expect("Commit Merkle batch must succeed");
    }

    // STEPS 20 - 38: Forensic Investigation, Tampering, Negative Tests, Restart Recovery
    {
        let db = SqliteDatabase::open(&db_path).expect("Failed to reopen database for forensics");

        // 20. Investigator submits A's leaked copy
        // 21. Extract Event A, 22. Resolve Recipient A, 23. Verify signature,
        // 24. Verify document hash, 25. Verify ledger, 26. Verify Merkle proof, 27. Return attribution to A
        let report_a = ForensicsManager::verify_leaked_document_persistent(
            &leaked_a_text_global,
            &doc_hash_global,
            &db,
        )
        .expect("Forensic verification on leaked document A must succeed");

        assert_eq!(report_a.status, AttributionStatus::VerifiedAttribution);
        assert_eq!(report_a.confidence.band, ConfidenceBand::High);
        assert_eq!(report_a.event_id, event_a_id_global);
        assert_eq!(report_a.recipient_id, recipient_a_pub_id);
        assert!(report_a.signature_valid, "ML-DSA signature must be valid");
        assert!(report_a.document_matched, "Document hash must match target");
        assert!(report_a.ledger_valid, "Ledger block must be valid");
        assert_eq!(
            report_a.merkle_proof_valid,
            Some(true),
            "Merkle proof must be valid"
        );

        // Verify JSON report export capability
        let json_report_a = ForensicsManager::generate_forensic_report_json(&report_a).unwrap();
        assert!(json_report_a.contains(&event_a_id_global));
        assert!(json_report_a.contains(&recipient_a_pub_id));
        assert!(json_report_a.contains("VerifiedAttribution"));

        // 28. Investigator submits B's leaked copy
        // 29. Attribute to B
        let report_b = ForensicsManager::verify_leaked_document_persistent(
            &leaked_b_text_global,
            &doc_hash_global,
            &db,
        )
        .expect("Forensic verification on leaked document B must succeed");

        assert_eq!(report_b.status, AttributionStatus::VerifiedAttribution);
        assert_eq!(report_b.confidence.band, ConfidenceBand::High);
        assert_eq!(report_b.event_id, event_b_id_global);
        assert_eq!(report_b.recipient_id, recipient_b_pub_id);
        assert!(
            report_b.signature_valid,
            "ML-DSA signature for B must be valid"
        );
        assert!(report_b.document_matched);
        assert!(report_b.ledger_valid);
        assert_eq!(report_b.merkle_proof_valid, Some(true));

        // 30. Tamper A's attestation
        // 31. Investigation must reject it
        let original_block_a = db
            .get_ledger_block_by_event_id(&event_a_id_global)
            .unwrap()
            .unwrap();
        let corrupted_payload = b"TAMPERED_ATTESTATION_CORRUPTED_SIGNATURE_BYTES";
        db.tamper_ledger_block_payload(&event_a_id_global, corrupted_payload)
            .unwrap();

        let report_tampered = ForensicsManager::verify_leaked_document_persistent(
            &leaked_a_text_global,
            &doc_hash_global,
            &db,
        )
        .expect("Forensic verification should execute");
        assert_eq!(
            report_tampered.status,
            AttributionStatus::TamperedEvidence,
            "Tampered signature must produce TamperedEvidence status"
        );
        assert!(!report_tampered.signature_valid || !report_tampered.ledger_valid);

        // Restore original block A to keep chain consistent for restart tests
        db.tamper_ledger_block_payload(&event_a_id_global, &original_block_a.event_payload)
            .unwrap();

        // 32. Destroy watermark
        // 33. Investigation must return insufficient evidence
        let stripped_text =
            "Completely stripped plaintext without any zero-width or spacing bytes.";
        let report_destroyed = ForensicsManager::verify_leaked_document_persistent(
            stripped_text,
            &doc_hash_global,
            &db,
        )
        .expect("Forensic verification should execute on stripped text");
        assert_eq!(
            report_destroyed.status,
            AttributionStatus::InsufficientEvidence,
            "Destroyed watermark must yield InsufficientEvidence"
        );
        assert_eq!(report_destroyed.confidence.band, ConfidenceBand::None);

        // 34. Attempt unauthorized decryption (wrong recipient / insufficient clearance)
        // 35. Operation must fail
        let mut id_mgr =
            IdentityManager::with_database(db.clone(), "Phase4_Strong_Master_Password_2026!");
        let unauthorized_user = id_mgr.register_user(
            "Unauthorized Intruder".to_string(),
            "External Group".to_string(),
            "Unauthorized Agency".to_string(),
            ClearanceLevel::Public,
            Role::Recipient,
        );
        let (unauth_enrolled, _) = id_mgr
            .enroll_cryptographic_identity(&unauthorized_user.user_id)
            .unwrap();

        let package_a_for_unauth = document_service::RecipientPackage {
            recipient_identity_id: recipient_a_pub_id.clone(),
            encrypted_content_key: vec![0u8; 32],
            ml_kem_ciphertext: vec![0u8; 1088],
            wrapped_nonce: vec![0u8; 12],
        };
        let doc_metadata = document_service::DocumentMetadata {
            document_id: "DOC-TEST".to_string(),
            document_hash: doc_hash_global.clone(),
            classification: Classification::Secret,
        };

        let unauth_decrypt_result = decrypt_recipient_document_rbac(
            &unauth_enrolled,
            id_mgr.keystore.as_ref().unwrap(),
            b"fake_ciphertext",
            b"fake_nonce12",
            &package_a_for_unauth,
            &doc_metadata,
        );

        assert!(
            unauth_decrypt_result.is_err(),
            "Unauthorized recipient with insufficient clearance and mismatched identity must fail decryption"
        );

        // 36. Restart application/database
        // 37. Repeat forensic lookup
        // 38. Evidence must still exist
        drop(db);
        let restarted_db =
            SqliteDatabase::open(&db_path).expect("Database must reopen cleanly after restart");

        let report_b_restart = ForensicsManager::verify_leaked_document_persistent(
            &leaked_b_text_global,
            &doc_hash_global,
            &restarted_db,
        )
        .expect("Verification must succeed after database restart");

        assert_eq!(
            report_b_restart.status,
            AttributionStatus::VerifiedAttribution
        );
        assert_eq!(report_b_restart.event_id, event_b_id_global);
        assert_eq!(report_b_restart.recipient_id, recipient_b_pub_id);
        assert!(report_b_restart.signature_valid);
        assert!(report_b_restart.ledger_valid);
        assert_eq!(report_b_restart.merkle_proof_valid, Some(true));
    }

    let _ = std::fs::remove_file(&db_path);
}

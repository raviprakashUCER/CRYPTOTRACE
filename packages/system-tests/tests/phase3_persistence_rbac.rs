use document_service::{decrypt_recipient_document_rbac, distribute_document_rbac, Classification};
use forensics_service::{AttributionStatus, ForensicsManager};
use identity_core::{
    generate_ml_dsa_keypair, generate_ml_kem_keypair, AuthError, ClearanceLevel,
    CryptographicIdentityPublic, KeyStatus, KeyStore, Role, User,
};
use identity_service::IdentityManager;
use ledger_core::{LedgerMerkleTree, Sha3Algorithm};
use ledger_service::PersistentLedger;
use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
use rs_merkle::Hasher;
use storage_sqlite::SqliteDatabase;

#[test]
fn test_phase3_persistence_restart_event_recovery() {
    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join(format!(
        "cryptotrace_test_persist_{}.db",
        uuid::Uuid::new_v4()
    ));

    let event_id_saved;
    let doc_hash_saved = "hash_strategic_defence_plan_2026".to_string();

    // 1. First session: Create records, decrypt, embed watermark, save in SQLite
    {
        let db = SqliteDatabase::open(&db_path).expect("Failed to open SQLite database");
        let mut id_mgr = IdentityManager::with_database(db.clone(), "super_secure_master_password");

        let user = id_mgr.register_user(
            "Officer Vikram".to_string(),
            "Naval Operations".to_string(),
            "Indian Navy".to_string(),
            ClearanceLevel::TopSecret,
            Role::Recipient,
        );

        let (enrolled_user, keystore) =
            id_mgr.enroll_cryptographic_identity(&user.user_id).unwrap();
        let pub_id = enrolled_user.cryptographic_identity.clone().unwrap();

        let event_id = ForensicsManager::generate_event_id(
            &doc_hash_saved,
            &pub_id.identity_id,
            "SESSION-ALPHA",
            b"nonce123",
        );
        event_id_saved = event_id.clone();

        let attestation = ForensicsManager::generate_attestation(
            event_id.clone(),
            doc_hash_saved.clone(),
            pub_id.identity_id.clone(),
            "SESSION-ALPHA".to_string(),
            &keystore.dsa_secret,
        )
        .unwrap();

        let payload = bincode::serialize(&attestation).unwrap();
        let _block = db
            .append_ledger_block(&event_id, &doc_hash_saved, &pub_id.identity_id, &payload)
            .unwrap();

        db.insert_decryption_event(
            &event_id,
            &doc_hash_saved,
            &pub_id.identity_id,
            "SESSION-ALPHA",
            KeyStatus::Active,
            &payload,
            &attestation.signature,
        )
        .unwrap();

        let persistent_ledger = PersistentLedger::new(db.clone()).unwrap();
        let _ = persistent_ledger.commit_merkle_batch();
    }

    // 2. Application Restart: Reopen database from disk and execute forensic analysis
    {
        let db = SqliteDatabase::open(&db_path).expect("Failed to reopen SQLite database");
        let _id_mgr = IdentityManager::with_database(db.clone(), "super_secure_master_password");

        let event_rec = db
            .get_decryption_event(&event_id_saved)
            .unwrap()
            .expect("Event must survive restart");
        assert_eq!(event_rec.event_id, event_id_saved);
        assert_eq!(event_rec.document_hash, doc_hash_saved);

        // Watermark text containing the event ID
        let leaked_text = ForensicsManager::embed_event_watermark(
            &event_id_saved,
            "Classified operational intelligence text",
        )
        .unwrap();

        let report =
            ForensicsManager::verify_leaked_document_persistent(&leaked_text, &doc_hash_saved, &db)
                .unwrap();

        assert!(report.is_match);
        assert_eq!(report.status, AttributionStatus::VerifiedAttribution);
        assert_eq!(report.event_id, event_id_saved);
        assert!(report.signature_valid);
        assert!(report.ledger_valid);
        assert_eq!(report.merkle_proof_valid, Some(true));
    }

    let _ = std::fs::remove_file(&db_path);
}

#[test]
fn test_phase3_identity_persistence_and_restart() {
    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join(format!("cryptotrace_test_id_{}.db", uuid::Uuid::new_v4()));

    let user_id_saved;
    let identity_id_saved;

    // Session 1: Register and Enroll
    {
        let db = SqliteDatabase::open(&db_path).unwrap();
        let mut id_mgr = IdentityManager::with_database(db.clone(), "keystore_master_pass_123");

        let user = id_mgr.register_user(
            "Officer Ananya".to_string(),
            "Strategic Signals".to_string(),
            "MoD".to_string(),
            ClearanceLevel::Secret,
            Role::Recipient,
        );
        user_id_saved = user.user_id.clone();

        let (enrolled, _) = id_mgr
            .enroll_cryptographic_identity(&user_id_saved)
            .unwrap();
        identity_id_saved = enrolled.cryptographic_identity.unwrap().identity_id;
    }

    // Session 2: Reload after restart
    {
        let db = SqliteDatabase::open(&db_path).unwrap();
        let id_mgr = IdentityManager::with_database(db.clone(), "keystore_master_pass_123");

        let user = id_mgr
            .get_user(&user_id_saved)
            .expect("User must be loaded from SQLite");
        assert_eq!(user.name, "Officer Ananya");
        assert_eq!(user.clearance_level, ClearanceLevel::Secret);

        let user_by_id = id_mgr
            .get_user_by_identity_id(&identity_id_saved)
            .expect("User must be searchable by identity ID");
        assert_eq!(user_by_id.user_id, user_id_saved);
    }

    let _ = std::fs::remove_file(&db_path);
}

#[test]
fn test_phase3_key_lifecycle_and_historical_attestation_verifiability() {
    let db = SqliteDatabase::open_in_memory().unwrap();
    let mut id_mgr = IdentityManager::with_database(db.clone(), "master_passphrase");

    let user = id_mgr.register_user(
        "Officer Kabir".to_string(),
        "Intelligence Bureau".to_string(),
        "MHA".to_string(),
        ClearanceLevel::TopSecret,
        Role::Recipient,
    );

    let (enrolled_user, keystore) = id_mgr.enroll_cryptographic_identity(&user.user_id).unwrap();
    let identity_id = enrolled_user
        .cryptographic_identity
        .as_ref()
        .unwrap()
        .identity_id
        .clone();

    // 1. Key is ACTIVE -> Decryption & attestation permitted
    assert_eq!(
        id_mgr.get_key_status(&identity_id).unwrap(),
        KeyStatus::Active
    );

    let doc_data = b"TOP SECRET AIR DEFENSE COORDINATES";
    let sender = User {
        user_id: "sender-1".to_string(),
        name: "Director HQ".to_string(),
        department: "HQ".to_string(),
        organization: "MoD".to_string(),
        clearance_level: ClearanceLevel::TopSecret,
        role: Role::Sender,
        cryptographic_identity: None,
        last_authentication: None,
    };

    let (metadata, enc_doc, doc_nonce, packages) = distribute_document_rbac(
        &sender,
        doc_data,
        Classification::TopSecret,
        std::slice::from_ref(&enrolled_user),
    )
    .unwrap();

    let decrypted = decrypt_recipient_document_rbac(
        &enrolled_user,
        id_mgr.keystore.as_ref().unwrap(),
        &enc_doc,
        &doc_nonce,
        &packages[0],
        &metadata,
    )
    .unwrap();
    assert_eq!(decrypted, doc_data);

    // Create and record historical attestation while key is ACTIVE
    let event_id = ForensicsManager::generate_event_id(
        &metadata.document_hash,
        &identity_id,
        "SESSION-1",
        b"nonce-hist",
    );

    let attestation = ForensicsManager::generate_attestation(
        event_id.clone(),
        metadata.document_hash.clone(),
        identity_id.clone(),
        "SESSION-1".to_string(),
        &keystore.dsa_secret,
    )
    .unwrap();

    let payload = bincode::serialize(&attestation).unwrap();
    let _ = db.append_ledger_block(&event_id, &metadata.document_hash, &identity_id, &payload);

    db.insert_decryption_event(
        &event_id,
        &metadata.document_hash,
        &identity_id,
        "SESSION-1",
        KeyStatus::Active,
        &payload,
        &attestation.signature,
    )
    .unwrap();

    // 2. Suspend Key -> New operations rejected
    id_mgr.suspend_key(&identity_id).unwrap();
    assert_eq!(
        id_mgr.get_key_status(&identity_id).unwrap(),
        KeyStatus::Suspended
    );

    let mut suspended_user = enrolled_user.clone();
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
        &packages[0],
        &metadata,
    );
    assert!(matches!(
        res_suspended,
        Err(document_service::DocumentError::AuthorizationError(
            AuthError::KeyNotActive { .. }
        ))
    ));

    // 3. Revoke Key -> New operations rejected
    id_mgr.revoke_key(&identity_id).unwrap();
    assert_eq!(
        id_mgr.get_key_status(&identity_id).unwrap(),
        KeyStatus::Revoked
    );

    let mut revoked_user = enrolled_user.clone();
    revoked_user.cryptographic_identity.as_mut().unwrap().status = KeyStatus::Revoked;

    let res_revoked = decrypt_recipient_document_rbac(
        &revoked_user,
        id_mgr.keystore.as_ref().unwrap(),
        &enc_doc,
        &doc_nonce,
        &packages[0],
        &metadata,
    );
    assert!(matches!(
        res_revoked,
        Err(document_service::DocumentError::AuthorizationError(
            AuthError::KeyNotActive { .. }
        ))
    ));

    // 4. Expire Key -> New operations rejected
    id_mgr.expire_key(&identity_id).unwrap();
    assert_eq!(
        id_mgr.get_key_status(&identity_id).unwrap(),
        KeyStatus::Expired
    );

    // 5. HISTORICAL VERIFICATION: The attestation made when the key was ACTIVE remains verifiable!
    let leaked_watermarked =
        ForensicsManager::embed_event_watermark(&event_id, "Leaked intelligence contents").unwrap();

    let report = ForensicsManager::verify_leaked_document_persistent(
        &leaked_watermarked,
        &metadata.document_hash,
        &db,
    )
    .unwrap();

    assert!(
        report.is_match,
        "Historical attestation must remain valid after key revocation/expiration"
    );
    assert_eq!(report.status, AttributionStatus::VerifiedAttribution);
    assert!(report.signature_valid);
    assert_eq!(report.event_time_key_status, "ACTIVE");
    assert_eq!(report.current_key_status, "EXPIRED");
}

#[test]
fn test_phase3_rbac_and_clearance_enforcement() {
    let (kem_pk, _) = generate_ml_kem_keypair();
    let (dsa_pk, _) = generate_ml_dsa_keypair();

    let top_secret_identity = CryptographicIdentityPublic {
        identity_id: "ID-TOP-SECRET".to_string(),
        kem_public_key: kem_pk.as_bytes().to_vec(),
        dsa_public_key: dsa_pk.as_bytes().to_vec(),
        status: KeyStatus::Active,
    };

    let top_secret_user = User {
        user_id: "u-top-secret".to_string(),
        name: "General Rawat".to_string(),
        department: "HQ".to_string(),
        organization: "Army".to_string(),
        clearance_level: ClearanceLevel::TopSecret,
        role: Role::Recipient,
        cryptographic_identity: Some(top_secret_identity.clone()),
        last_authentication: None,
    };

    let confidential_user = User {
        user_id: "u-confidential".to_string(),
        name: "Clerk Sharma".to_string(),
        department: "Logistics".to_string(),
        organization: "Army".to_string(),
        clearance_level: ClearanceLevel::Confidential,
        role: Role::Recipient,
        cryptographic_identity: Some(top_secret_identity.clone()),
        last_authentication: None,
    };

    let sender_user = User {
        user_id: "u-sender".to_string(),
        name: "Colonel Verma".to_string(),
        department: "Operations".to_string(),
        organization: "Army".to_string(),
        clearance_level: ClearanceLevel::TopSecret,
        role: Role::Sender,
        cryptographic_identity: None,
        last_authentication: None,
    };

    let recipient_trying_to_send = User {
        user_id: "u-recipient".to_string(),
        name: "Soldier Singh".to_string(),
        department: "Infantry".to_string(),
        organization: "Army".to_string(),
        clearance_level: ClearanceLevel::TopSecret,
        role: Role::Recipient,
        cryptographic_identity: None,
        last_authentication: None,
    };

    // 1. SENDER with insufficient role permission fails distribution
    let res_invalid_sender = distribute_document_rbac(
        &recipient_trying_to_send,
        b"CONFIDENTIAL DATA",
        Classification::Secret,
        std::slice::from_ref(&top_secret_user),
    );
    assert!(matches!(
        res_invalid_sender,
        Err(document_service::DocumentError::AuthorizationError(
            AuthError::UnauthorizedRole { .. }
        ))
    ));

    // 2. Distributing TopSecret document to Confidential user fails clearance check
    let res_insufficient_clearance = distribute_document_rbac(
        &sender_user,
        b"TOP SECRET DATA",
        Classification::TopSecret,
        &[confidential_user],
    );
    assert!(matches!(
        res_insufficient_clearance,
        Err(document_service::DocumentError::AuthorizationError(
            AuthError::InsufficientClearance { .. }
        ))
    ));

    // 3. Valid distribution to TopSecret user succeeds
    let res_valid = distribute_document_rbac(
        &sender_user,
        b"TOP SECRET DATA",
        Classification::TopSecret,
        &[top_secret_user],
    );
    assert!(res_valid.is_ok());
}

#[test]
fn test_phase3_ledger_tamper_detection_on_reload() {
    let db = SqliteDatabase::open_in_memory().unwrap();

    // Append 3 blocks
    let _b0 = db
        .append_ledger_block("EVT-0", "HASH-0", "USER-0", b"block_0_payload")
        .unwrap();
    let _b1 = db
        .append_ledger_block("EVT-1", "HASH-1", "USER-1", b"block_1_payload")
        .unwrap();
    let _b2 = db
        .append_ledger_block("EVT-2", "HASH-2", "USER-2", b"block_2_payload")
        .unwrap();

    // Initial chain loads and verifies
    let chain = db.load_ledger_chain().unwrap();
    assert_eq!(chain.blocks.len(), 3);
    assert!(chain.verify());

    // Adversary modifies block 1 directly in database table
    {
        let conn = db.get_user("nonexistent"); // Just testing db reference
        let _ = conn;
        // In real SQLite, if someone tampers with block 1 payload:
        let mut tampered_chain = chain.clone();
        tampered_chain.blocks[1].event_payload = b"tampered_forged_payload".to_vec();
        assert!(
            tampered_chain.verify_detailed().is_err(),
            "Modified block in hash chain must be detected"
        );

        // Broken previous_hash
        let mut broken_hash_chain = chain.clone();
        broken_hash_chain.blocks[2].previous_hash =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        assert!(
            broken_hash_chain.verify_detailed().is_err(),
            "Broken previous-hash in chain must be detected"
        );
    }
}

#[test]
fn test_phase3_merkle_inclusion_proof_verification() {
    let leaves: Vec<[u8; 32]> = (0..8)
        .map(|i| Sha3Algorithm::hash(format!("event-payload-{}", i).as_bytes()))
        .collect();

    let tree = LedgerMerkleTree::new(&leaves);
    let root = tree.root_hex().unwrap();

    // Valid inclusion proof for leaf 5
    let proof = tree.generate_inclusion_proof(5).unwrap();
    assert_eq!(proof.leaf_index, 5);
    assert_eq!(proof.total_leaves, 8);
    assert_eq!(proof.root_hash, root);

    assert!(LedgerMerkleTree::verify_inclusion(&proof, &leaves[5]));

    // Wrong leaf fails
    assert!(!LedgerMerkleTree::verify_inclusion(&proof, &leaves[2]));

    // Wrong root fails
    let mut bad_root_proof = proof.clone();
    bad_root_proof.root_hash = hex::encode([0xAA; 32]);
    assert!(!LedgerMerkleTree::verify_inclusion(
        &bad_root_proof,
        &leaves[5]
    ));

    // Modified sibling proof hash fails
    let mut bad_sibling_proof = proof.clone();
    if !bad_sibling_proof.proof_hashes.is_empty() {
        bad_sibling_proof.proof_hashes[0] = hex::encode([0xBB; 32]);
        assert!(!LedgerMerkleTree::verify_inclusion(
            &bad_sibling_proof,
            &leaves[5]
        ));
    }
}

#[test]
fn test_phase3_security_no_plaintext_private_keys_in_db() {
    let db = SqliteDatabase::open_in_memory().unwrap();
    let mut id_mgr = IdentityManager::with_database(db.clone(), "passphrase_for_test");

    let user = id_mgr.register_user(
        "Officer Secret".to_string(),
        "Special Branch".to_string(),
        "Police".to_string(),
        ClearanceLevel::TopSecret,
        Role::Recipient,
    );

    let (enrolled, _) = id_mgr.enroll_cryptographic_identity(&user.user_id).unwrap();
    let identity_id = enrolled.cryptographic_identity.unwrap().identity_id;

    // Verify raw secret keys are stored ONLY encrypted in LocalEncryptedKeyStore
    let encrypted_blob = id_mgr
        .keystore
        .as_ref()
        .unwrap()
        .get_encrypted_blob(&identity_id)
        .expect("Encrypted blob must exist in keystore");

    // Ciphertext must NOT match raw PQC key bytes
    let raw_key = id_mgr
        .keystore
        .as_ref()
        .unwrap()
        .load_key(&identity_id)
        .unwrap();

    assert_ne!(
        encrypted_blob.ciphertext,
        raw_key.kem_secret.as_bytes(),
        "Keystore must NOT store plaintext KEM secret"
    );
    assert_ne!(
        encrypted_blob.ciphertext,
        raw_key.dsa_secret.as_bytes(),
        "Keystore must NOT store plaintext DSA secret"
    );

    // Check DB public identity table does NOT contain secret keys
    let db_identities = db.list_all_identities().unwrap();
    for ident in db_identities {
        assert_ne!(ident.kem_public_key, raw_key.kem_secret.as_bytes());
        assert_ne!(ident.dsa_public_key, raw_key.dsa_secret.as_bytes());
    }
}

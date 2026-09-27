use document_service::{
    decrypt_recipient_document, detect_document_format, distribute_document, ingest_document,
    DocumentMetadata, IngestedDocument, RecipientPackage,
};
use forensics_service::{ForensicReport, ForensicsManager};
use identity_service::{ClearanceLevel, IdentityManager, KeyStatus, ProtectedKeystore, Role};
use ledger_core::{LedgerMerkleTree, Sha3Algorithm};
use ledger_service::{LedgerNetwork, PersistentLedger};
use rs_merkle::Hasher;
use std::collections::HashMap;
use std::sync::Mutex;
use storage_sqlite::{AuditLogRecord, SqliteDatabase};
use tauri::State;
use watermark_core::DocumentFormat;

#[derive(Clone)]
pub struct DistributedDocumentRecord {
    pub metadata: DocumentMetadata,
    pub title: String,
    pub encrypted_doc: Vec<u8>,
    pub doc_nonce: Vec<u8>,
    pub recipient_packages: Vec<RecipientPackage>,
    pub created_at: String,
}

// Shared Application State
pub struct AppState {
    pub db: Mutex<SqliteDatabase>,
    pub identity_manager: Mutex<IdentityManager>,
    pub ledger: Mutex<LedgerNetwork>,
    pub persistent_ledger: Mutex<PersistentLedger>,
    pub mock_keystore: Mutex<HashMap<String, ProtectedKeystore>>,
    pub distributed_documents: Mutex<HashMap<String, DistributedDocumentRecord>>,
    pub ingested_documents: Mutex<HashMap<String, IngestedDocument>>,
}

#[tauri::command]
fn get_system_status() -> String {
    "System Online - All Cryptographic Core & Persistence Modules Loaded".to_string()
}

// User representation for frontend
#[derive(serde::Serialize)]
pub struct UserResponse {
    pub id: String,
    pub name: String,
    pub department: String,
    pub clearance: String,
    pub role: String,
    pub status: String,
}

#[tauri::command]
fn get_users(state: State<'_, AppState>) -> Result<Vec<UserResponse>, String> {
    let id_mgr = state.identity_manager.lock().unwrap();
    let users = id_mgr
        .users
        .values()
        .map(|u| UserResponse {
            id: u.user_id.clone(),
            name: u.name.clone(),
            department: u.department.clone(),
            clearance: u.clearance_level.to_string(),
            role: u.role.to_string(),
            status: u
                .cryptographic_identity
                .as_ref()
                .map(|i| i.status.to_string())
                .unwrap_or_else(|| "UNENROLLED".to_string()),
        })
        .collect();
    Ok(users)
}

#[tauri::command]
fn register_user(
    name: String,
    department: String,
    clearance: String,
    role_str: String,
    state: State<'_, AppState>,
) -> Result<UserResponse, String> {
    let mut id_mgr = state.identity_manager.lock().unwrap();
    let mut keystore_map = state.mock_keystore.lock().unwrap();
    let db = state.db.lock().unwrap();

    let role = Role::from_str_loose(&role_str);
    let clearance_level = ClearanceLevel::from_str_loose(&clearance);

    let user = id_mgr.register_user(
        name.clone(),
        department.clone(),
        "Government of India".to_string(),
        clearance_level,
        role,
    );
    let recipient_id = user.user_id.clone();

    // Enroll cryptographic identity for the user
    let (updated_user, keystore) = id_mgr
        .enroll_cryptographic_identity(&recipient_id)
        .map_err(|e| format!("Enrollment failed: {}", e))?;

    let _ = db.insert_user(&updated_user);
    keystore_map.insert(recipient_id.clone(), keystore);

    Ok(UserResponse {
        id: updated_user.user_id.clone(),
        name: updated_user.name.clone(),
        department: updated_user.department.clone(),
        clearance: updated_user.clearance_level.to_string(),
        role: updated_user.role.to_string(),
        status: updated_user
            .cryptographic_identity
            .as_ref()
            .map(|i| i.status.to_string())
            .unwrap_or_else(|| "ACTIVE".to_string()),
    })
}

#[tauri::command]
fn update_key_status(
    identity_id: String,
    status_str: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let mut id_mgr = state.identity_manager.lock().unwrap();
    let db = state.db.lock().unwrap();
    let new_status = KeyStatus::from_str_loose(&status_str);
    match new_status {
        KeyStatus::Active => id_mgr.activate_key(&identity_id)?,
        KeyStatus::Suspended => id_mgr.suspend_key(&identity_id)?,
        KeyStatus::Revoked => id_mgr.revoke_key(&identity_id)?,
        KeyStatus::Expired => id_mgr.expire_key(&identity_id)?,
        _ => id_mgr.revoke_key(&identity_id)?,
    };
    let _ = db.update_identity_status(&identity_id, new_status);
    Ok(format!("Key status updated to {}", new_status))
}

#[tauri::command]
fn update_user_role(
    user_id: String,
    role_str: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let mut id_mgr = state.identity_manager.lock().unwrap();
    let db = state.db.lock().unwrap();
    let new_role = Role::from_str_loose(&role_str);
    id_mgr
        .update_user_role(&user_id, new_role, Role::Admin)
        .map_err(|e| format!("{:?}", e))?;
    let _ = db.update_user_role(&user_id, new_role);
    Ok(format!("User role updated to {}", new_role))
}

#[tauri::command]
fn get_audit_logs(state: State<'_, AppState>) -> Result<Vec<AuditLogRecord>, String> {
    let db = state.db.lock().unwrap();
    db.list_audit_logs().map_err(|e| format!("{:?}", e))
}

#[derive(serde::Serialize)]
pub struct IngestResponse {
    pub document_id: String,
    pub filename: String,
    pub mime_type: String,
    pub file_size: usize,
    pub document_hash: String,
    pub classification: String,
    pub creator: String,
    pub format: String,
    pub watermarking_supported: bool,
}

#[tauri::command]
fn ingest_document_command(
    filename: String,
    mime_type: Option<String>,
    content: String,
    classification_str: String,
    creator: String,
    state: State<'_, AppState>,
) -> Result<IngestResponse, String> {
    let mut ingested_store = state.ingested_documents.lock().unwrap();
    let db = state.db.lock().unwrap();
    let classification = ClearanceLevel::from_str_loose(&classification_str);

    let data = content.as_bytes();
    let ingested = ingest_document(
        data,
        &filename,
        mime_type.as_deref(),
        classification,
        &creator,
    )
    .map_err(|e| format!("Ingestion Error: {:?}", e))?;

    let watermarking_supported = matches!(
        ingested.format,
        DocumentFormat::PlainText | DocumentFormat::Utf8Markdown
    );

    let resp = IngestResponse {
        document_id: ingested.document_id.clone(),
        filename: ingested.filename.clone(),
        mime_type: ingested.mime_type.clone(),
        file_size: ingested.file_size,
        document_hash: ingested.document_hash.clone(),
        classification: classification.to_string(),
        creator: ingested.creator.clone(),
        format: format!("{:?}", ingested.format),
        watermarking_supported,
    };

    let _ = db.insert_audit_log(
        "DOCUMENT_INGESTED",
        &creator,
        &ingested.document_id,
        &format!(
            "Ingested {} ({}, {} bytes)",
            filename, ingested.document_hash, ingested.file_size
        ),
        "SUCCESS",
    );

    ingested_store.insert(ingested.document_id.clone(), ingested);
    Ok(resp)
}

#[derive(serde::Serialize)]
pub struct DocumentRecordResponse {
    pub id: String,
    pub title: String,
    pub hash: String,
    pub classification: String,
    pub encrypted_at: String,
    pub size_bytes: u64,
    pub recipient_count: usize,
    pub is_distributed: bool,
}

#[tauri::command]
fn get_documents(state: State<'_, AppState>) -> Result<Vec<DocumentRecordResponse>, String> {
    let db = state.db.lock().unwrap();
    let docs = db.list_documents().map_err(|e| format!("{:?}", e))?;
    let resp = docs
        .into_iter()
        .map(|d| {
            let pkgs = db
                .list_distribution_packages_for_document(&d.document_id)
                .unwrap_or_default();
            DocumentRecordResponse {
                id: d.document_id,
                title: d.title,
                hash: d.document_hash,
                classification: d.classification.to_string(),
                encrypted_at: d.created_at,
                size_bytes: d.encrypted_data.len() as u64,
                recipient_count: pkgs.len(),
                is_distributed: !pkgs.is_empty(),
            }
        })
        .collect();
    Ok(resp)
}

#[tauri::command]
fn distribute(
    title: String,
    content: String,
    recipient_ids: Vec<String>,
    classification_str: Option<String>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let id_mgr = state.identity_manager.lock().unwrap();
    let db = state.db.lock().unwrap();
    let mut doc_store = state.distributed_documents.lock().unwrap();

    if recipient_ids.is_empty() {
        return Err("No recipients selected".to_string());
    }

    let classification = classification_str
        .map(|c| ClearanceLevel::from_str_loose(&c))
        .unwrap_or(ClearanceLevel::Secret);

    let mut recipient_pub_keys = Vec::new();
    for rid in &recipient_ids {
        if let Some(user) = id_mgr.users.get(rid) {
            // Check clearance
            if !user.clearance_level.can_access(classification) {
                return Err(format!(
                    "Recipient {} has insufficient clearance ({}) for classification ({})",
                    rid, user.clearance_level, classification
                ));
            }
            if let Some(ref pub_id) = user.cryptographic_identity {
                if !pub_id.status.can_operate() {
                    return Err(format!(
                        "Recipient {} key status is {} (must be ACTIVE)",
                        rid, pub_id.status
                    ));
                }
                recipient_pub_keys.push(pub_id.clone());
            } else {
                return Err(format!("User {} has no cryptographic identity", rid));
            }
        } else {
            return Err(format!("User {} not found", rid));
        }
    }

    let document_data = content.as_bytes();
    let (metadata, encrypted_doc, doc_nonce, recipient_packages) =
        distribute_document(document_data, classification, &recipient_pub_keys)
            .map_err(|e| format!("Crypto Error: {:?}", e))?;

    let document_id = metadata.document_id.clone();
    let doc_record = DistributedDocumentRecord {
        metadata: metadata.clone(),
        title: title.clone(),
        encrypted_doc: encrypted_doc.clone(),
        doc_nonce: doc_nonce.clone(),
        recipient_packages: recipient_packages.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    doc_store.insert(document_id.clone(), doc_record);

    // Save to SQLite
    let _ = db.insert_document(
        &document_id,
        &metadata.document_hash,
        &title,
        classification,
        &encrypted_doc,
        &doc_nonce,
        "OFFICER_DISPATCH",
    );

    for pkg in &recipient_packages {
        let _ = db.insert_distribution_package(
            &document_id,
            &pkg.recipient_identity_id,
            &pkg.ml_kem_ciphertext,
            &pkg.encrypted_content_key,
            &pkg.wrapped_nonce,
        );
    }

    let _ = db.insert_audit_log(
        "DOCUMENT_DISTRIBUTED",
        "DISPATCHER",
        &document_id,
        &format!("Distributed to {} recipients", recipient_ids.len()),
        "SUCCESS",
    );

    Ok(format!(
        "Document successfully encrypted and distributed to {} recipient(s). Document ID: {}",
        recipient_ids.len(),
        document_id
    ))
}

#[derive(serde::Serialize)]
pub struct AuthorizedPackageResponse {
    pub document_id: String,
    pub title: String,
    pub document_hash: String,
    pub classification: String,
    pub sender: String,
    pub distributed_at: String,
    pub key_status: String,
}

#[tauri::command]
fn get_authorized_packages_for_recipient(
    recipient_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<AuthorizedPackageResponse>, String> {
    let db = state.db.lock().unwrap();
    let id_mgr = state.identity_manager.lock().unwrap();

    let user = id_mgr
        .users
        .get(&recipient_id)
        .ok_or_else(|| format!("User {} not found", recipient_id))?;

    let identity_id = user
        .cryptographic_identity
        .as_ref()
        .map(|i| i.identity_id.clone())
        .unwrap_or_else(|| recipient_id.clone());

    let packages = db
        .list_distribution_packages_for_recipient(&identity_id)
        .unwrap_or_default();

    let mut result = Vec::new();
    for pkg in packages {
        if let Ok(Some(doc)) = db.get_document_by_id(&pkg.document_id) {
            result.push(AuthorizedPackageResponse {
                document_id: doc.document_id,
                title: doc.title,
                document_hash: doc.document_hash,
                classification: doc.classification.to_string(),
                sender: doc.created_by,
                distributed_at: pkg.distributed_at,
                key_status: user
                    .cryptographic_identity
                    .as_ref()
                    .map(|i| i.status.to_string())
                    .unwrap_or_else(|| "UNKNOWN".to_string()),
            });
        }
    }
    Ok(result)
}

#[derive(serde::Serialize)]
pub struct DecryptionResponse {
    pub watermarked_plaintext: String,
    pub event_id: String,
    pub recipient_id: String,
    pub document_hash: String,
    pub attestation_signature: String,
    pub ledger_committed: bool,
    pub key_status_at_event: String,
}

#[tauri::command]
fn decrypt_document(
    document_id: String,
    recipient_id: String,
    session_id: String,
    state: State<'_, AppState>,
) -> Result<DecryptionResponse, String> {
    let doc_store = state.distributed_documents.lock().unwrap();
    let keystore_map = state.mock_keystore.lock().unwrap();
    let mut ledger = state.ledger.lock().unwrap();
    let mut persistent_ledger = state.persistent_ledger.lock().unwrap();
    let db = state.db.lock().unwrap();
    let id_mgr = state.identity_manager.lock().unwrap();

    let user = id_mgr
        .users
        .get(&recipient_id)
        .ok_or_else(|| format!("User {} not found", recipient_id))?;

    let identity = user
        .cryptographic_identity
        .as_ref()
        .ok_or_else(|| format!("User {} has no active cryptographic identity", recipient_id))?;

    if !identity.status.can_operate() {
        return Err(format!(
            "Access Denied: Recipient key is {} (must be ACTIVE)",
            identity.status
        ));
    }

    let doc = doc_store
        .get(&document_id)
        .ok_or_else(|| format!("Document {} not found", document_id))?;

    let package = doc
        .recipient_packages
        .iter()
        .find(|p| {
            p.recipient_identity_id == identity.identity_id
                || p.recipient_identity_id == recipient_id
        })
        .ok_or_else(|| format!("No package for recipient {}", recipient_id))?;

    let keystore = keystore_map
        .get(&recipient_id)
        .or_else(|| keystore_map.get(&identity.identity_id))
        .ok_or_else(|| format!("Keystore not found for recipient {}", recipient_id))?;

    // 1. Decrypt document using recipient's ML-KEM secret key
    let plaintext_bytes = decrypt_recipient_document(
        &doc.encrypted_doc,
        &doc.doc_nonce,
        package,
        &doc.metadata.document_hash,
        &keystore.kem_secret,
    )
    .map_err(|e| format!("Decryption failed: {:?}", e))?;

    let plaintext_str = String::from_utf8(plaintext_bytes)
        .map_err(|e| format!("Plaintext decoding failed: {:?}", e))?;

    // 2. Generate unique per-session Event ID
    let nonce = b"session_nonce_sec";
    let event_id = ForensicsManager::generate_event_id(
        &doc.metadata.document_hash,
        &recipient_id,
        &session_id,
        nonce,
    );

    // 3. Generate ML-DSA attestation signed by recipient
    let attestation = ForensicsManager::generate_attestation(
        event_id.clone(),
        doc.metadata.document_hash.clone(),
        recipient_id.clone(),
        session_id.clone(),
        &keystore.dsa_secret,
    )
    .map_err(|e| format!("Attestation signing failed: {:?}", e))?;

    // 4. Commit event to offline ledger & persistent ledger
    ledger
        .broadcast_event(attestation.clone())
        .map_err(|e| format!("Ledger append failed: {:?}", e))?;

    let _ = persistent_ledger.record_attestation(&attestation);

    // Record decryption event in DB
    let att_payload = bincode::serialize(&attestation).unwrap_or_default();
    let _ = db.insert_decryption_event(
        &event_id,
        &doc.metadata.document_hash,
        &recipient_id,
        &session_id,
        KeyStatus::Active,
        &att_payload,
        &attestation.signature,
    );

    // 5. Embed watermark into plaintext
    let watermarked_plaintext = ForensicsManager::embed_event_watermark(&event_id, &plaintext_str)
        .map_err(|e| format!("Watermark embedding failed: {:?}", e))?;

    Ok(DecryptionResponse {
        watermarked_plaintext,
        event_id,
        recipient_id,
        document_hash: doc.metadata.document_hash.clone(),
        attestation_signature: hex::encode(&attestation.signature),
        ledger_committed: true,
        key_status_at_event: "ACTIVE".to_string(),
    })
}

#[tauri::command]
fn verify_leak(
    leaked_text: String,
    expected_hash: String,
    filename: Option<String>,
    state: State<'_, AppState>,
) -> Result<ForensicReport, String> {
    let ledger = state.ledger.lock().unwrap();
    let id_mgr = state.identity_manager.lock().unwrap();

    let fname = filename.unwrap_or_else(|| "leaked_artifact.txt".to_string());
    let format = detect_document_format(&fname, None);

    if !matches!(
        format,
        DocumentFormat::PlainText | DocumentFormat::Utf8Markdown
    ) {
        return Ok(ForensicsManager::investigate_unsupported_format(
            &fname, format,
        ));
    }

    // Build identity registry mapping both user_id and identity_id to public identities
    let mut identity_registry = HashMap::new();
    for user in id_mgr.users.values() {
        if let Some(ref ident) = user.cryptographic_identity {
            identity_registry.insert(user.user_id.clone(), ident.clone());
            identity_registry.insert(ident.identity_id.clone(), ident.clone());
        }
    }

    if identity_registry.is_empty() {
        return Err("No registered cryptographic identities found".to_string());
    }

    let mut report = ForensicsManager::verify_leaked_document_with_registry(
        &leaked_text,
        &expected_hash,
        &ledger.nodes[0].chain,
        &identity_registry,
    )
    .map_err(|e| format!("{:?}", e))?;

    report.investigated_file = fname;
    Ok(report)
}

#[derive(serde::Serialize)]
pub struct LedgerVerificationResult {
    pub chain_valid: bool,
    pub block_count: usize,
    pub latest_hash: String,
    pub errors: Vec<String>,
}

#[tauri::command]
fn verify_ledger_chain(state: State<'_, AppState>) -> Result<LedgerVerificationResult, String> {
    let db = state.db.lock().unwrap();
    let chain = db.load_ledger_chain().map_err(|e| format!("{:?}", e))?;
    let valid = chain.verify();
    let count = chain.blocks.len();
    let latest_hash = chain
        .blocks
        .last()
        .map(|b| b.current_hash.clone())
        .unwrap_or_else(|| "GENESIS".to_string());

    Ok(LedgerVerificationResult {
        chain_valid: valid,
        block_count: count,
        latest_hash,
        errors: if valid {
            Vec::new()
        } else {
            vec!["Ledger hash-chain integrity verification failed".to_string()]
        },
    })
}

#[derive(serde::Serialize)]
pub struct MerkleProofVerificationResult {
    pub event_id: String,
    pub is_proven: bool,
    pub merkle_root: String,
    pub proof_path_len: usize,
}

#[tauri::command]
fn verify_merkle_proof(
    event_id: String,
    state: State<'_, AppState>,
) -> Result<MerkleProofVerificationResult, String> {
    let db = state.db.lock().unwrap();
    let chain = db.load_ledger_chain().map_err(|e| format!("{:?}", e))?;

    let leaves: Vec<[u8; 32]> = chain
        .blocks
        .iter()
        .map(|b| Sha3Algorithm::hash(&b.event_payload))
        .collect();

    let tree = LedgerMerkleTree::new(&leaves);
    let root = tree
        .root_hex()
        .unwrap_or_else(|| "EMPTY_MERKLE_ROOT".to_string());

    if let Some(pos) = chain.blocks.iter().position(|b| {
        if let Ok(att) =
            bincode::deserialize::<forensics_service::DecryptionAttestation>(&b.event_payload)
        {
            att.event_id == event_id
        } else {
            false
        }
    }) {
        let proof = tree
            .generate_inclusion_proof(pos)
            .map_err(|e| format!("{:?}", e))?;
        let leaf = Sha3Algorithm::hash(&chain.blocks[pos].event_payload);
        let valid = LedgerMerkleTree::verify_inclusion(&proof, &leaf);

        Ok(MerkleProofVerificationResult {
            event_id,
            is_proven: valid,
            merkle_root: root,
            proof_path_len: proof.proof_hashes.len(),
        })
    } else {
        Err(format!("Event ID {} not found in ledger blocks", event_id))
    }
}

#[tauri::command]
fn export_forensic_report_json(report: ForensicReport) -> Result<String, String> {
    ForensicsManager::generate_forensic_report_json(&report).map_err(|e| format!("{:?}", e))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let db = SqliteDatabase::open_in_memory().expect("failed to open sqlite database");
    let persistent_ledger =
        PersistentLedger::new(db.clone()).expect("failed to init persistent ledger");

    tauri::Builder::default()
        .plugin(tauri_plugin_log::Builder::new().build())
        .manage(AppState {
            db: Mutex::new(db),
            identity_manager: Mutex::new(IdentityManager::new()),
            ledger: Mutex::new(LedgerNetwork::new(5, 3)),
            persistent_ledger: Mutex::new(persistent_ledger),
            mock_keystore: Mutex::new(HashMap::new()),
            distributed_documents: Mutex::new(HashMap::new()),
            ingested_documents: Mutex::new(HashMap::new()),
        })
        .invoke_handler(tauri::generate_handler![
            get_system_status,
            get_users,
            register_user,
            update_key_status,
            update_user_role,
            get_audit_logs,
            ingest_document_command,
            get_documents,
            distribute,
            get_authorized_packages_for_recipient,
            decrypt_document,
            verify_leak,
            verify_ledger_chain,
            verify_merkle_proof,
            export_forensic_report_json
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

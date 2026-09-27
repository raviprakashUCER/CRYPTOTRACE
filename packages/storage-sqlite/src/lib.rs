#![allow(clippy::too_many_arguments)]

use chrono::Utc;
use identity_core::{ClearanceLevel, CryptographicIdentityPublic, KeyStatus, Role, User};
use ledger_core::{HashChain, LedgerBlock, Sha3Algorithm};
use rs_merkle::Hasher;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    SqliteError(#[from] rusqlite::Error),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Integrity error: {0}")]
    IntegrityError(String),
    #[error("Record not found: {0}")]
    NotFound(String),
    #[error("Lock error")]
    LockError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentRecord {
    pub document_id: String,
    pub document_hash: String,
    pub title: String,
    pub classification: ClearanceLevel,
    pub encrypted_data: Vec<u8>,
    pub doc_nonce: Vec<u8>,
    pub created_by: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributionPackageRecord {
    pub id: String,
    pub document_id: String,
    pub recipient_identity_id: String,
    pub ml_kem_ciphertext: Vec<u8>,
    pub encrypted_content_key: Vec<u8>,
    pub wrapped_nonce: Vec<u8>,
    pub distributed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionEventRecord {
    pub event_id: String,
    pub document_hash: String,
    pub recipient_id: String,
    pub session_id: String,
    pub decrypted_at: String,
    pub key_status_at_event: KeyStatus,
    pub attestation_payload: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleBatchRecord {
    pub batch_id: String,
    pub merkle_root: String,
    pub start_seq: i64,
    pub end_seq: i64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogRecord {
    pub id: i64,
    pub action: String,
    pub actor_id: String,
    pub target_resource: String,
    pub details: String,
    pub timestamp: String,
    pub status: String,
}

#[derive(Clone)]
pub struct SqliteDatabase {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteDatabase {
    /// Opens an in-memory SQLite database initialized with the CRYPTOTRACE schema.
    pub fn open_in_memory() -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.init_schema()?;
        Ok(db)
    }

    /// Opens a persistent SQLite database at the specified file path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;

        // Enable foreign keys & WAL mode
        conn.execute_batch(
            r#"
            PRAGMA foreign_keys = ON;
            PRAGMA journal_mode = WAL;

            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                department TEXT NOT NULL,
                organization TEXT NOT NULL,
                clearance_level TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cryptographic_identities (
                identity_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                kem_public_key BLOB NOT NULL,
                dsa_public_key BLOB NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS documents (
                document_id TEXT PRIMARY KEY,
                document_hash TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                classification TEXT NOT NULL,
                encrypted_data BLOB NOT NULL,
                doc_nonce BLOB NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS document_distributions (
                id TEXT PRIMARY KEY,
                document_id TEXT NOT NULL REFERENCES documents(document_id) ON DELETE CASCADE,
                recipient_identity_id TEXT NOT NULL,
                ml_kem_ciphertext BLOB NOT NULL,
                encrypted_content_key BLOB NOT NULL,
                wrapped_nonce BLOB NOT NULL,
                distributed_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS decryption_events (
                event_id TEXT PRIMARY KEY,
                document_hash TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                decrypted_at TEXT NOT NULL,
                key_status_at_event TEXT NOT NULL,
                attestation_payload BLOB NOT NULL,
                signature BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ledger_blocks (
                sequence_num INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                document_hash TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_payload BLOB NOT NULL,
                current_hash TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS merkle_batches (
                batch_id TEXT PRIMARY KEY,
                merkle_root TEXT NOT NULL,
                start_seq INTEGER NOT NULL,
                end_seq INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                target_resource TEXT NOT NULL,
                details TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                status TEXT NOT NULL
            );

            -- Indexes for high performance querying
            CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
            CREATE INDEX IF NOT EXISTS idx_identities_status ON cryptographic_identities(status);
            CREATE INDEX IF NOT EXISTS idx_documents_hash ON documents(document_hash);
            CREATE INDEX IF NOT EXISTS idx_distributions_doc_recip ON document_distributions(document_id, recipient_identity_id);
            CREATE INDEX IF NOT EXISTS idx_events_event_id ON decryption_events(event_id);
            CREATE INDEX IF NOT EXISTS idx_events_doc_hash ON decryption_events(document_hash);
            CREATE INDEX IF NOT EXISTS idx_events_recipient ON decryption_events(recipient_id);
            CREATE INDEX IF NOT EXISTS idx_ledger_current_hash ON ledger_blocks(current_hash);
            CREATE INDEX IF NOT EXISTS idx_ledger_event_id ON ledger_blocks(event_id);
            CREATE INDEX IF NOT EXISTS idx_ledger_seq ON ledger_blocks(sequence_num);
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs(actor_id);
            "#,
        )?;

        Ok(())
    }

    // ------------------------------------------------------------------------
    // USER & IDENTITY REPOSITORY
    // ------------------------------------------------------------------------

    pub fn insert_user(&self, user: &User) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;
        let now = Utc::now().to_rfc3339();

        conn.execute(
            r#"
            INSERT INTO users (user_id, name, department, organization, clearance_level, role, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(user_id) DO UPDATE SET
                name=excluded.name,
                department=excluded.department,
                organization=excluded.organization,
                clearance_level=excluded.clearance_level,
                role=excluded.role
            "#,
            params![
                user.user_id,
                user.name,
                user.department,
                user.organization,
                user.clearance_level.to_string(),
                user.role.to_string(),
                now,
            ],
        )?;

        if let Some(ref identity) = user.cryptographic_identity {
            conn.execute(
                r#"
                INSERT INTO cryptographic_identities (identity_id, user_id, kem_public_key, dsa_public_key, status, created_at, updated_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                ON CONFLICT(identity_id) DO UPDATE SET
                    status=excluded.status,
                    updated_at=excluded.updated_at
                "#,
                params![
                    identity.identity_id,
                    user.user_id,
                    identity.kem_public_key,
                    identity.dsa_public_key,
                    identity.status.to_string(),
                    now,
                    now,
                ],
            )?;
        }

        Ok(())
    }

    pub fn get_user(&self, user_id: &str) -> Result<Option<User>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;

        let mut stmt = conn.prepare(
            r#"
            SELECT u.user_id, u.name, u.department, u.organization, u.clearance_level, u.role,
                   ci.identity_id, ci.kem_public_key, ci.dsa_public_key, ci.status
            FROM users u
            LEFT JOIN cryptographic_identities ci ON u.user_id = ci.user_id
            WHERE u.user_id = ?1
            "#,
        )?;

        let mut rows = stmt.query(params![user_id])?;
        if let Some(row) = rows.next()? {
            let user_id: String = row.get(0)?;
            let name: String = row.get(1)?;
            let department: String = row.get(2)?;
            let organization: String = row.get(3)?;
            let clearance_str: String = row.get(4)?;
            let role_str: String = row.get(5)?;

            let identity_id: Option<String> = row.get(6)?;
            let kem_pk: Option<Vec<u8>> = row.get(7)?;
            let dsa_pk: Option<Vec<u8>> = row.get(8)?;
            let status_str: Option<String> = row.get(9)?;

            let cryptographic_identity = match (identity_id, kem_pk, dsa_pk, status_str) {
                (Some(id), Some(kem), Some(dsa), Some(st)) => Some(CryptographicIdentityPublic {
                    identity_id: id,
                    kem_public_key: kem,
                    dsa_public_key: dsa,
                    status: KeyStatus::from_str_loose(&st),
                }),
                _ => None,
            };

            Ok(Some(User {
                user_id,
                name,
                department,
                organization,
                clearance_level: ClearanceLevel::from_str_loose(&clearance_str),
                role: Role::from_str_loose(&role_str),
                cryptographic_identity,
                last_authentication: None,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn get_user_by_identity_id(&self, identity_id: &str) -> Result<Option<User>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;

        let mut stmt = conn.prepare(
            r#"
            SELECT u.user_id, u.name, u.department, u.organization, u.clearance_level, u.role,
                   ci.identity_id, ci.kem_public_key, ci.dsa_public_key, ci.status
            FROM cryptographic_identities ci
            JOIN users u ON ci.user_id = u.user_id
            WHERE ci.identity_id = ?1
            "#,
        )?;

        let mut rows = stmt.query(params![identity_id])?;
        if let Some(row) = rows.next()? {
            let user_id: String = row.get(0)?;
            let name: String = row.get(1)?;
            let department: String = row.get(2)?;
            let organization: String = row.get(3)?;
            let clearance_str: String = row.get(4)?;
            let role_str: String = row.get(5)?;

            let id_val: String = row.get(6)?;
            let kem_pk: Vec<u8> = row.get(7)?;
            let dsa_pk: Vec<u8> = row.get(8)?;
            let status_str: String = row.get(9)?;

            let cryptographic_identity = Some(CryptographicIdentityPublic {
                identity_id: id_val,
                kem_public_key: kem_pk,
                dsa_public_key: dsa_pk,
                status: KeyStatus::from_str_loose(&status_str),
            });

            Ok(Some(User {
                user_id,
                name,
                department,
                organization,
                clearance_level: ClearanceLevel::from_str_loose(&clearance_str),
                role: Role::from_str_loose(&role_str),
                cryptographic_identity,
                last_authentication: None,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn list_users(&self) -> Result<Vec<User>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;

        let mut stmt = conn.prepare(
            r#"
            SELECT u.user_id, u.name, u.department, u.organization, u.clearance_level, u.role,
                   ci.identity_id, ci.kem_public_key, ci.dsa_public_key, ci.status
            FROM users u
            LEFT JOIN cryptographic_identities ci ON u.user_id = ci.user_id
            ORDER BY u.created_at ASC
            "#,
        )?;

        let mut users = Vec::new();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let user_id: String = row.get(0)?;
            let name: String = row.get(1)?;
            let department: String = row.get(2)?;
            let organization: String = row.get(3)?;
            let clearance_str: String = row.get(4)?;
            let role_str: String = row.get(5)?;

            let identity_id: Option<String> = row.get(6)?;
            let kem_pk: Option<Vec<u8>> = row.get(7)?;
            let dsa_pk: Option<Vec<u8>> = row.get(8)?;
            let status_str: Option<String> = row.get(9)?;

            let cryptographic_identity = match (identity_id, kem_pk, dsa_pk, status_str) {
                (Some(id), Some(kem), Some(dsa), Some(st)) => Some(CryptographicIdentityPublic {
                    identity_id: id,
                    kem_public_key: kem,
                    dsa_public_key: dsa,
                    status: KeyStatus::from_str_loose(&st),
                }),
                _ => None,
            };

            users.push(User {
                user_id,
                name,
                department,
                organization,
                clearance_level: ClearanceLevel::from_str_loose(&clearance_str),
                role: Role::from_str_loose(&role_str),
                cryptographic_identity,
                last_authentication: None,
            });
        }

        Ok(users)
    }

    pub fn update_user_role(&self, user_id: &str, role: Role) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;
        conn.execute(
            "UPDATE users SET role = ?1 WHERE user_id = ?2",
            params![role.to_string(), user_id],
        )?;
        Ok(())
    }

    pub fn update_identity_status(
        &self,
        identity_id: &str,
        status: KeyStatus,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE cryptographic_identities SET status = ?1, updated_at = ?2 WHERE identity_id = ?3",
            params![status.to_string(), now, identity_id],
        )?;
        Ok(())
    }

    pub fn get_identity(
        &self,
        identity_id: &str,
    ) -> Result<Option<CryptographicIdentityPublic>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;
        let mut stmt = conn.prepare(
            "SELECT identity_id, kem_public_key, dsa_public_key, status FROM cryptographic_identities WHERE identity_id = ?1",
        )?;

        let mut rows = stmt.query(params![identity_id])?;
        if let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let kem: Vec<u8> = row.get(1)?;
            let dsa: Vec<u8> = row.get(2)?;
            let st: String = row.get(3)?;

            Ok(Some(CryptographicIdentityPublic {
                identity_id: id,
                kem_public_key: kem,
                dsa_public_key: dsa,
                status: KeyStatus::from_str_loose(&st),
            }))
        } else {
            Ok(None)
        }
    }

    pub fn list_all_identities(&self) -> Result<Vec<CryptographicIdentityPublic>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;
        let mut stmt = conn.prepare(
            "SELECT identity_id, kem_public_key, dsa_public_key, status FROM cryptographic_identities",
        )?;

        let mut identities = Vec::new();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let kem: Vec<u8> = row.get(1)?;
            let dsa: Vec<u8> = row.get(2)?;
            let st: String = row.get(3)?;

            identities.push(CryptographicIdentityPublic {
                identity_id: id,
                kem_public_key: kem,
                dsa_public_key: dsa,
                status: KeyStatus::from_str_loose(&st),
            });
        }
        Ok(identities)
    }

    // ------------------------------------------------------------------------
    // DOCUMENT REPOSITORY
    // ------------------------------------------------------------------------

    pub fn insert_document(
        &self,
        doc_id: &str,
        doc_hash: &str,
        title: &str,
        classification: ClearanceLevel,
        encrypted_data: &[u8],
        doc_nonce: &[u8],
        created_by: &str,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;
        let now = Utc::now().to_rfc3339();

        conn.execute(
            r#"
            INSERT INTO documents (document_id, document_hash, title, classification, encrypted_data, doc_nonce, created_by, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                doc_id,
                doc_hash,
                title,
                classification.to_string(),
                encrypted_data,
                doc_nonce,
                created_by,
                now,
            ],
        )?;

        Ok(())
    }

    pub fn get_document_by_id(&self, doc_id: &str) -> Result<Option<DocumentRecord>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;
        let mut stmt = conn.prepare(
            r#"
            SELECT document_id, document_hash, title, classification, encrypted_data, doc_nonce, created_by, created_at
            FROM documents WHERE document_id = ?1
            "#,
        )?;

        let mut rows = stmt.query(params![doc_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(DocumentRecord {
                document_id: row.get(0)?,
                document_hash: row.get(1)?,
                title: row.get(2)?,
                classification: ClearanceLevel::from_str_loose(&row.get::<_, String>(3)?),
                encrypted_data: row.get(4)?,
                doc_nonce: row.get(5)?,
                created_by: row.get(6)?,
                created_at: row.get(7)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn get_document_by_hash(
        &self,
        doc_hash: &str,
    ) -> Result<Option<DocumentRecord>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;
        let mut stmt = conn.prepare(
            r#"
            SELECT document_id, document_hash, title, classification, encrypted_data, doc_nonce, created_by, created_at
            FROM documents WHERE document_hash = ?1
            "#,
        )?;

        let mut rows = stmt.query(params![doc_hash])?;
        if let Some(row) = rows.next()? {
            Ok(Some(DocumentRecord {
                document_id: row.get(0)?,
                document_hash: row.get(1)?,
                title: row.get(2)?,
                classification: ClearanceLevel::from_str_loose(&row.get::<_, String>(3)?),
                encrypted_data: row.get(4)?,
                doc_nonce: row.get(5)?,
                created_by: row.get(6)?,
                created_at: row.get(7)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn list_documents(&self) -> Result<Vec<DocumentRecord>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;
        let mut stmt = conn.prepare(
            r#"
            SELECT document_id, document_hash, title, classification, encrypted_data, doc_nonce, created_by, created_at
            FROM documents ORDER BY created_at DESC
            "#,
        )?;

        let mut docs = Vec::new();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            docs.push(DocumentRecord {
                document_id: row.get(0)?,
                document_hash: row.get(1)?,
                title: row.get(2)?,
                classification: ClearanceLevel::from_str_loose(&row.get::<_, String>(3)?),
                encrypted_data: row.get(4)?,
                doc_nonce: row.get(5)?,
                created_by: row.get(6)?,
                created_at: row.get(7)?,
            });
        }
        Ok(docs)
    }

    pub fn insert_distribution_package(
        &self,
        doc_id: &str,
        recipient_identity_id: &str,
        ml_kem_ciphertext: &[u8],
        encrypted_content_key: &[u8],
        wrapped_nonce: &[u8],
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        conn.execute(
            r#"
            INSERT INTO document_distributions (id, document_id, recipient_identity_id, ml_kem_ciphertext, encrypted_content_key, wrapped_nonce, distributed_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                id,
                doc_id,
                recipient_identity_id,
                ml_kem_ciphertext,
                encrypted_content_key,
                wrapped_nonce,
                now,
            ],
        )?;

        Ok(())
    }

    pub fn get_distribution_package(
        &self,
        doc_id: &str,
        recipient_identity_id: &str,
    ) -> Result<Option<DistributionPackageRecord>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;
        let mut stmt = conn.prepare(
            r#"
            SELECT id, document_id, recipient_identity_id, ml_kem_ciphertext, encrypted_content_key, wrapped_nonce, distributed_at
            FROM document_distributions
            WHERE document_id = ?1 AND recipient_identity_id = ?2
            "#,
        )?;

        let mut rows = stmt.query(params![doc_id, recipient_identity_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(DistributionPackageRecord {
                id: row.get(0)?,
                document_id: row.get(1)?,
                recipient_identity_id: row.get(2)?,
                ml_kem_ciphertext: row.get(3)?,
                encrypted_content_key: row.get(4)?,
                wrapped_nonce: row.get(5)?,
                distributed_at: row.get(6)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn list_distribution_packages_for_document(
        &self,
        doc_id: &str,
    ) -> Result<Vec<DistributionPackageRecord>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;
        let mut stmt = conn.prepare(
            r#"
            SELECT id, document_id, recipient_identity_id, ml_kem_ciphertext, encrypted_content_key, wrapped_nonce, distributed_at
            FROM document_distributions
            WHERE document_id = ?1
            ORDER BY distributed_at DESC
            "#,
        )?;

        let mut rows = stmt.query(params![doc_id])?;
        let mut packages = Vec::new();
        while let Some(row) = rows.next()? {
            packages.push(DistributionPackageRecord {
                id: row.get(0)?,
                document_id: row.get(1)?,
                recipient_identity_id: row.get(2)?,
                ml_kem_ciphertext: row.get(3)?,
                encrypted_content_key: row.get(4)?,
                wrapped_nonce: row.get(5)?,
                distributed_at: row.get(6)?,
            });
        }
        Ok(packages)
    }

    pub fn list_distribution_packages_for_recipient(
        &self,
        recipient_identity_id: &str,
    ) -> Result<Vec<DistributionPackageRecord>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;
        let mut stmt = conn.prepare(
            r#"
            SELECT id, document_id, recipient_identity_id, ml_kem_ciphertext, encrypted_content_key, wrapped_nonce, distributed_at
            FROM document_distributions
            WHERE recipient_identity_id = ?1
            ORDER BY distributed_at DESC
            "#,
        )?;

        let mut rows = stmt.query(params![recipient_identity_id])?;
        let mut packages = Vec::new();
        while let Some(row) = rows.next()? {
            packages.push(DistributionPackageRecord {
                id: row.get(0)?,
                document_id: row.get(1)?,
                recipient_identity_id: row.get(2)?,
                ml_kem_ciphertext: row.get(3)?,
                encrypted_content_key: row.get(4)?,
                wrapped_nonce: row.get(5)?,
                distributed_at: row.get(6)?,
            });
        }
        Ok(packages)
    }

    // ------------------------------------------------------------------------
    // DECRYPTION EVENTS & PROVENANCE REPOSITORY
    // ------------------------------------------------------------------------

    pub fn insert_decryption_event(
        &self,
        event_id: &str,
        doc_hash: &str,
        recipient_id: &str,
        session_id: &str,
        key_status_at_event: KeyStatus,
        attestation_payload: &[u8],
        signature: &[u8],
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;
        let now = Utc::now().to_rfc3339();

        conn.execute(
            r#"
            INSERT OR REPLACE INTO decryption_events (event_id, document_hash, recipient_id, session_id, decrypted_at, key_status_at_event, attestation_payload, signature)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                event_id,
                doc_hash,
                recipient_id,
                session_id,
                now,
                key_status_at_event.to_string(),
                attestation_payload,
                signature,
            ],
        )?;

        Ok(())
    }

    pub fn get_decryption_event(
        &self,
        event_id: &str,
    ) -> Result<Option<DecryptionEventRecord>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;
        let mut stmt = conn.prepare(
            r#"
            SELECT event_id, document_hash, recipient_id, session_id, decrypted_at, key_status_at_event, attestation_payload, signature
            FROM decryption_events WHERE event_id = ?1
            "#,
        )?;

        let mut rows = stmt.query(params![event_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(DecryptionEventRecord {
                event_id: row.get(0)?,
                document_hash: row.get(1)?,
                recipient_id: row.get(2)?,
                session_id: row.get(3)?,
                decrypted_at: row.get(4)?,
                key_status_at_event: KeyStatus::from_str_loose(&row.get::<_, String>(5)?),
                attestation_payload: row.get(6)?,
                signature: row.get(7)?,
            }))
        } else {
            Ok(None)
        }
    }

    // ------------------------------------------------------------------------
    // LEDGER PERSISTENCE & INTEGRITY REPOSITORY
    // ------------------------------------------------------------------------

    pub fn append_ledger_block(
        &self,
        event_id: &str,
        doc_hash: &str,
        recipient_id: &str,
        payload: &[u8],
    ) -> Result<LedgerBlock, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;

        // Find last block current_hash
        let mut stmt = conn.prepare(
            "SELECT sequence_num, current_hash FROM ledger_blocks ORDER BY sequence_num DESC LIMIT 1",
        )?;
        let last_block: Option<(i64, String)> = stmt
            .query_row([], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?;

        let (seq, previous_hash) = match last_block {
            Some((s, h)) => (s + 1, h),
            None => (
                0,
                String::from("0000000000000000000000000000000000000000000000000000000000000000"),
            ),
        };

        let mut data = Vec::new();
        data.extend_from_slice(previous_hash.as_bytes());
        data.extend_from_slice(payload);

        let current_hash = hex::encode(Sha3Algorithm::hash(&data));
        let timestamp = Utc::now().to_rfc3339();

        conn.execute(
            r#"
            INSERT INTO ledger_blocks (sequence_num, event_id, document_hash, recipient_id, previous_hash, event_payload, current_hash, timestamp)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                seq,
                event_id,
                doc_hash,
                recipient_id,
                previous_hash,
                payload,
                current_hash,
                timestamp,
            ],
        )?;

        Ok(LedgerBlock {
            sequence_num: Some(seq),
            previous_hash,
            event_payload: payload.to_vec(),
            current_hash,
            timestamp,
        })
    }

    pub fn load_ledger_chain(&self) -> Result<HashChain, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;
        let mut stmt = conn.prepare(
            r#"
            SELECT sequence_num, previous_hash, event_payload, current_hash, timestamp
            FROM ledger_blocks ORDER BY sequence_num ASC
            "#,
        )?;

        let mut blocks = Vec::new();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            blocks.push(LedgerBlock {
                sequence_num: Some(row.get(0)?),
                previous_hash: row.get(1)?,
                event_payload: row.get(2)?,
                current_hash: row.get(3)?,
                timestamp: row.get(4)?,
            });
        }

        let chain = HashChain { blocks };
        // Validate chain integrity immediately upon load
        if let Err(e) = chain.verify_detailed() {
            return Err(StorageError::IntegrityError(format!(
                "Ledger hash-chain verification failed upon reload: {:?}",
                e
            )));
        }

        Ok(chain)
    }

    pub fn get_ledger_block_by_event_id(
        &self,
        event_id: &str,
    ) -> Result<Option<LedgerBlock>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;
        let mut stmt = conn.prepare(
            r#"
            SELECT sequence_num, previous_hash, event_payload, current_hash, timestamp
            FROM ledger_blocks WHERE event_id = ?1
            "#,
        )?;

        let mut rows = stmt.query(params![event_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(LedgerBlock {
                sequence_num: Some(row.get(0)?),
                previous_hash: row.get(1)?,
                event_payload: row.get(2)?,
                current_hash: row.get(3)?,
                timestamp: row.get(4)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn get_ledger_block_count(&self) -> Result<usize, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM ledger_blocks", [], |r| r.get(0))?;
        Ok(count as usize)
    }

    /// For testing adversarial tamper detection on persistent ledger records
    pub fn tamper_ledger_block_payload(
        &self,
        event_id: &str,
        new_payload: &[u8],
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;
        conn.execute(
            "UPDATE ledger_blocks SET event_payload = ?1 WHERE event_id = ?2",
            params![new_payload, event_id],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------------
    // MERKLE BATCH REPOSITORY
    // ------------------------------------------------------------------------

    pub fn save_merkle_batch(
        &self,
        batch_id: &str,
        merkle_root: &str,
        start_seq: i64,
        end_seq: i64,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;
        let now = Utc::now().to_rfc3339();

        conn.execute(
            r#"
            INSERT INTO merkle_batches (batch_id, merkle_root, start_seq, end_seq, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![batch_id, merkle_root, start_seq, end_seq, now],
        )?;

        Ok(())
    }

    pub fn get_latest_merkle_batch(&self) -> Result<Option<MerkleBatchRecord>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;
        let mut stmt = conn.prepare(
            "SELECT batch_id, merkle_root, start_seq, end_seq, created_at FROM merkle_batches ORDER BY end_seq DESC LIMIT 1",
        )?;

        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            Ok(Some(MerkleBatchRecord {
                batch_id: row.get(0)?,
                merkle_root: row.get(1)?,
                start_seq: row.get(2)?,
                end_seq: row.get(3)?,
                created_at: row.get(4)?,
            }))
        } else {
            Ok(None)
        }
    }

    // ------------------------------------------------------------------------
    // AUDIT TRAIL REPOSITORY
    // ------------------------------------------------------------------------

    pub fn insert_audit_log(
        &self,
        action: &str,
        actor_id: &str,
        target_resource: &str,
        details: &str,
        status: &str,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;
        let now = Utc::now().to_rfc3339();

        conn.execute(
            r#"
            INSERT INTO audit_logs (action, actor_id, target_resource, details, timestamp, status)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![action, actor_id, target_resource, details, now, status],
        )?;

        Ok(())
    }

    pub fn list_audit_logs(&self) -> Result<Vec<AuditLogRecord>, StorageError> {
        let conn = self.conn.lock().map_err(|_| StorageError::LockError)?;
        let mut stmt = conn.prepare(
            "SELECT id, action, actor_id, target_resource, details, timestamp, status FROM audit_logs ORDER BY id DESC",
        )?;

        let mut logs = Vec::new();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            logs.push(AuditLogRecord {
                id: row.get(0)?,
                action: row.get(1)?,
                actor_id: row.get(2)?,
                target_resource: row.get(3)?,
                details: row.get(4)?,
                timestamp: row.get(5)?,
                status: row.get(6)?,
            });
        }
        Ok(logs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqlite_persistence_roundtrip() {
        let db = SqliteDatabase::open_in_memory().unwrap();

        let user = User {
            user_id: "user-123".to_string(),
            name: "Officer Test".to_string(),
            department: "Defense".to_string(),
            organization: "Gov".to_string(),
            clearance_level: ClearanceLevel::TopSecret,
            role: Role::Recipient,
            cryptographic_identity: None,
            last_authentication: None,
        };

        db.insert_user(&user).unwrap();
        let loaded = db.get_user("user-123").unwrap().unwrap();
        assert_eq!(loaded.name, "Officer Test");
        assert_eq!(loaded.clearance_level, ClearanceLevel::TopSecret);
        assert_eq!(loaded.role, Role::Recipient);

        // Test Ledger Block append & hash verification
        let b1 = db
            .append_ledger_block("EVT-1", "HASH-1", "REC-1", b"payload1")
            .unwrap();
        let b2 = db
            .append_ledger_block("EVT-2", "HASH-2", "REC-2", b"payload2")
            .unwrap();

        assert_eq!(b2.previous_hash, b1.current_hash);

        let chain = db.load_ledger_chain().unwrap();
        assert_eq!(chain.blocks.len(), 2);
        assert!(chain.verify());
    }
}

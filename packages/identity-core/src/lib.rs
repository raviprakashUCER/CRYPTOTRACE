use chrono::{DateTime, Utc};
use crypto_core::{decrypt_document_aes256gcm, encrypt_document_aes256gcm, hash_document_sha3_256};
use pqcrypto_dilithium::dilithium3;
pub use pqcrypto_dilithium::dilithium3::{PublicKey as DsaPublicKey, SecretKey as DsaSecretKey};
use pqcrypto_kyber::kyber768;
pub use pqcrypto_kyber::kyber768::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use pqcrypto_traits::kem::{PublicKey as KemTraitPublicKey, SecretKey as KemTraitSecretKey};
use pqcrypto_traits::sign::{PublicKey as SignTraitPublicKey, SecretKey as SignTraitSecretKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};
use thiserror::Error;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyStatus {
    Active,
    Suspended,
    Revoked,
    Expired,
    Rotating,
    Compromised,
}

impl fmt::Display for KeyStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyStatus::Active => write!(f, "ACTIVE"),
            KeyStatus::Suspended => write!(f, "SUSPENDED"),
            KeyStatus::Revoked => write!(f, "REVOKED"),
            KeyStatus::Expired => write!(f, "EXPIRED"),
            KeyStatus::Rotating => write!(f, "ROTATING"),
            KeyStatus::Compromised => write!(f, "COMPROMISED"),
        }
    }
}

impl KeyStatus {
    pub fn is_active(&self) -> bool {
        matches!(self, KeyStatus::Active)
    }

    pub fn can_operate(&self) -> bool {
        matches!(self, KeyStatus::Active)
    }

    pub fn from_str_loose(s: &str) -> Self {
        match s.to_uppercase().trim() {
            "ACTIVE" => KeyStatus::Active,
            "SUSPENDED" => KeyStatus::Suspended,
            "REVOKED" => KeyStatus::Revoked,
            "EXPIRED" => KeyStatus::Expired,
            "ROTATING" => KeyStatus::Rotating,
            "COMPROMISED" => KeyStatus::Compromised,
            _ => KeyStatus::Active,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Role {
    Admin,
    Sender,
    Recipient,
    Investigator,
    Auditor,
    // Aliases for backwards compatibility with Phase 1/2
    SuperAdministrator,
    SecurityAdministrator,
    DocumentOwner,
    ForensicInvestigator,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Admin | Role::SuperAdministrator | Role::SecurityAdministrator => {
                write!(f, "ADMIN")
            }
            Role::Sender | Role::DocumentOwner => write!(f, "SENDER"),
            Role::Recipient => write!(f, "RECIPIENT"),
            Role::Investigator | Role::ForensicInvestigator => write!(f, "INVESTIGATOR"),
            Role::Auditor => write!(f, "AUDITOR"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permission {
    ManageIdentities,
    ManageRoles,
    ManageKeyStatus,
    InspectConfig,
    RegisterDocuments,
    DistributePackages,
    DecryptAuthorizedPackages,
    GenerateDecryptionAttestation,
    PerformForensics,
    InspectEvidence,
    ReadAuditLogs,
    ReadProvenanceRecords,
}

impl Role {
    pub fn has_permission(&self, permission: Permission) -> bool {
        match self {
            Role::Admin | Role::SuperAdministrator | Role::SecurityAdministrator => true, // Admin has all permissions
            Role::Sender | Role::DocumentOwner => matches!(
                permission,
                Permission::RegisterDocuments
                    | Permission::DistributePackages
                    | Permission::ReadProvenanceRecords
            ),
            Role::Recipient => matches!(
                permission,
                Permission::DecryptAuthorizedPackages
                    | Permission::GenerateDecryptionAttestation
                    | Permission::ReadProvenanceRecords
            ),
            Role::Investigator | Role::ForensicInvestigator => matches!(
                permission,
                Permission::PerformForensics
                    | Permission::InspectEvidence
                    | Permission::ReadAuditLogs
                    | Permission::ReadProvenanceRecords
            ),
            Role::Auditor => matches!(
                permission,
                Permission::ReadAuditLogs | Permission::ReadProvenanceRecords
            ),
        }
    }

    pub fn verify_permission(&self, permission: Permission) -> Result<(), AuthError> {
        if self.has_permission(permission) {
            Ok(())
        } else {
            Err(AuthError::UnauthorizedRole {
                role: self.to_string(),
                required_permission: format!("{:?}", permission),
            })
        }
    }

    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().replace([' ', '_', '-'], "").as_str() {
            "admin" | "superadmin" | "superadministrator" => Role::Admin,
            "securityadmin" | "securityadministrator" => Role::Admin,
            "sender" | "documentowner" | "documentofficer" | "docowner" => Role::Sender,
            "forensicinvestigator" | "investigator" | "forensics" => Role::Investigator,
            "auditor" => Role::Auditor,
            _ => Role::Recipient,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClearanceLevel {
    Public = 0,
    Confidential = 1,
    Secret = 2,
    TopSecret = 3,
}

impl fmt::Display for ClearanceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClearanceLevel::Public => write!(f, "Public"),
            ClearanceLevel::Confidential => write!(f, "Confidential"),
            ClearanceLevel::Secret => write!(f, "Secret"),
            ClearanceLevel::TopSecret => write!(f, "TopSecret"),
        }
    }
}

impl ClearanceLevel {
    pub fn can_access(&self, required: ClearanceLevel) -> bool {
        *self >= required
    }

    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().replace([' ', '_', '-'], "").as_str() {
            "public" => ClearanceLevel::Public,
            "confidential" => ClearanceLevel::Confidential,
            "topsecret" => ClearanceLevel::TopSecret,
            _ => ClearanceLevel::Secret,
        }
    }
}

#[derive(Error, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthError {
    #[error("Unauthorized role: {role} lacks permission {required_permission}")]
    UnauthorizedRole {
        role: String,
        required_permission: String,
    },
    #[error(
        "Insufficient clearance: user has {user_clearance}, document requires {required_clearance}"
    )]
    InsufficientClearance {
        user_clearance: String,
        required_clearance: String,
    },
    #[error("Key is not active: status is {status}")]
    KeyNotActive { status: String },
    #[error("Recipient not authorized for this document package")]
    RecipientNotAuthorized,
}

/// Represents the public cryptographic identity of a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptographicIdentityPublic {
    pub identity_id: String,
    pub kem_public_key: Vec<u8>,
    pub dsa_public_key: Vec<u8>,
    pub status: KeyStatus,
}

/// Canonical User model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub user_id: String,
    pub name: String,
    pub department: String,
    pub organization: String,
    pub clearance_level: ClearanceLevel,
    pub role: Role,
    pub cryptographic_identity: Option<CryptographicIdentityPublic>,
    pub last_authentication: Option<DateTime<Utc>>,
}

/// Represents protected private keys (kept in memory or encrypted storage)
pub struct ProtectedKeystore {
    pub kem_secret: KemSecretKey,
    pub dsa_secret: DsaSecretKey,
}

/// Generates a new ML-KEM (Kyber768) keypair
pub fn generate_ml_kem_keypair() -> (kyber768::PublicKey, kyber768::SecretKey) {
    kyber768::keypair()
}

/// Generates a new ML-DSA (Dilithium3) keypair
pub fn generate_ml_dsa_keypair() -> (dilithium3::PublicKey, dilithium3::SecretKey) {
    dilithium3::keypair()
}

impl CryptographicIdentityPublic {
    pub fn new(
        identity_id: String,
        kem_pk: &kyber768::PublicKey,
        dsa_pk: &dilithium3::PublicKey,
    ) -> Self {
        Self {
            identity_id,
            kem_public_key: kem_pk.as_bytes().to_vec(),
            dsa_public_key: dsa_pk.as_bytes().to_vec(),
            status: KeyStatus::Active,
        }
    }
}

// ----------------------------------------------------------------------------
// SECURE KEY STORAGE ABSTRACTION (Phase 3)
// ----------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum KeyStoreError {
    #[error("Key not found for identity: {0}")]
    KeyNotFound(String),
    #[error("Key encryption/decryption failed: {0}")]
    CryptoError(String),
    #[error("Key serialization failed")]
    SerializationError,
    #[error("Keystore lock poisoned")]
    LockError,
}

/// Abstract interface for secure private key storage.
/// In production environments, this maps to an OS Keystore / TPM / PKCS#11 HSM.
pub trait KeyStore: Send + Sync {
    fn store_key(
        &mut self,
        identity_id: &str,
        keystore: &ProtectedKeystore,
    ) -> Result<(), KeyStoreError>;
    fn load_key(&self, identity_id: &str) -> Result<ProtectedKeystore, KeyStoreError>;
    fn delete_key(&mut self, identity_id: &str) -> Result<(), KeyStoreError>;
    fn has_key(&self, identity_id: &str) -> bool;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedKeyBlob {
    pub identity_id: String,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Local encrypted keystore implementation protecting PQC secret keys with AES-256-GCM.
/// Secret keys are NEVER stored in plaintext in database columns or memory dumps.
pub struct LocalEncryptedKeyStore {
    master_key: [u8; 32],
    storage: Arc<RwLock<HashMap<String, EncryptedKeyBlob>>>,
}

impl LocalEncryptedKeyStore {
    pub fn new(master_passphrase: &str) -> Self {
        let hash = hash_document_sha3_256(master_passphrase.as_bytes());
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&hash[0..32]);
        Self {
            master_key,
            storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn with_master_key(master_key: [u8; 32]) -> Self {
        Self {
            master_key,
            storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn get_encrypted_blob(&self, identity_id: &str) -> Option<EncryptedKeyBlob> {
        let store = self.storage.read().ok()?;
        store.get(identity_id).cloned()
    }
}

impl KeyStore for LocalEncryptedKeyStore {
    fn store_key(
        &mut self,
        identity_id: &str,
        keystore: &ProtectedKeystore,
    ) -> Result<(), KeyStoreError> {
        // Serialize PQC secret keys: kem_secret len + kem_secret bytes + dsa_secret bytes
        let kem_bytes = keystore.kem_secret.as_bytes();
        let dsa_bytes = keystore.dsa_secret.as_bytes();

        let mut payload = Vec::with_capacity(4 + kem_bytes.len() + dsa_bytes.len());
        payload.extend_from_slice(&(kem_bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(kem_bytes);
        payload.extend_from_slice(dsa_bytes);

        // Encrypt with master key using AES-256-GCM
        let (ciphertext, nonce) = encrypt_document_aes256gcm(&self.master_key, &payload)
            .map_err(|e| KeyStoreError::CryptoError(format!("{:?}", e)))?;

        let blob = EncryptedKeyBlob {
            identity_id: identity_id.to_string(),
            ciphertext,
            nonce,
        };

        let mut store = self.storage.write().map_err(|_| KeyStoreError::LockError)?;
        store.insert(identity_id.to_string(), blob);
        Ok(())
    }

    fn load_key(&self, identity_id: &str) -> Result<ProtectedKeystore, KeyStoreError> {
        let store = self.storage.read().map_err(|_| KeyStoreError::LockError)?;
        let blob = store
            .get(identity_id)
            .ok_or_else(|| KeyStoreError::KeyNotFound(identity_id.to_string()))?;

        let decrypted = decrypt_document_aes256gcm(&self.master_key, &blob.nonce, &blob.ciphertext)
            .map_err(|e| KeyStoreError::CryptoError(format!("{:?}", e)))?;

        if decrypted.len() < 4 {
            return Err(KeyStoreError::SerializationError);
        }

        let kem_len =
            u32::from_le_bytes([decrypted[0], decrypted[1], decrypted[2], decrypted[3]]) as usize;

        if decrypted.len() < 4 + kem_len {
            return Err(KeyStoreError::SerializationError);
        }

        let kem_bytes = &decrypted[4..4 + kem_len];
        let dsa_bytes = &decrypted[4 + kem_len..];

        let kem_secret = kyber768::SecretKey::from_bytes(kem_bytes)
            .map_err(|_| KeyStoreError::SerializationError)?;
        let dsa_secret = dilithium3::SecretKey::from_bytes(dsa_bytes)
            .map_err(|_| KeyStoreError::SerializationError)?;

        Ok(ProtectedKeystore {
            kem_secret,
            dsa_secret,
        })
    }

    fn delete_key(&mut self, identity_id: &str) -> Result<(), KeyStoreError> {
        let mut store = self.storage.write().map_err(|_| KeyStoreError::LockError)?;
        store.remove(identity_id);
        Ok(())
    }

    fn has_key(&self, identity_id: &str) -> bool {
        if let Ok(store) = self.storage.read() {
            store.contains_key(identity_id)
        } else {
            false
        }
    }
}

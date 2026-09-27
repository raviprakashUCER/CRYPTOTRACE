#![allow(clippy::type_complexity)]

use chrono::Utc;
use crypto_core::{
    decrypt_document_aes256gcm, derive_kek_hkdf, encrypt_document_aes256gcm, hash_document_sha3_256,
};
use identity_core::{
    AuthError, ClearanceLevel, CryptographicIdentityPublic, KeyStore, Permission, User,
};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
pub use watermark_core::DocumentFormat;
use watermark_core::WatermarkError;

pub type Classification = ClearanceLevel;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestedDocument {
    pub document_id: String,
    pub filename: String,
    pub mime_type: String,
    pub file_size: usize,
    pub document_hash: String,
    pub classification: Classification,
    pub creator: String,
    pub creation_timestamp: String,
    pub format: DocumentFormat,
    pub raw_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentMetadata {
    pub document_id: String,
    pub document_hash: String,
    pub classification: Classification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientPackage {
    pub recipient_identity_id: String,
    pub ml_kem_ciphertext: Vec<u8>,
    pub encrypted_content_key: Vec<u8>,
    pub wrapped_nonce: Vec<u8>,
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum DocumentError {
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
    #[error("Invalid key")]
    InvalidKey,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Authorization error: {0}")]
    AuthorizationError(#[from] AuthError),
    #[error("Key store error: {0}")]
    KeyStoreError(String),
    #[error("UNSUPPORTED_WATERMARK_FORMAT: {0:?}")]
    UnsupportedWatermarkFormat(DocumentFormat),
    #[error("Watermark error: {0}")]
    WatermarkError(String),
    #[error("Empty document bytes")]
    EmptyDocument,
}

impl From<WatermarkError> for DocumentError {
    fn from(err: WatermarkError) -> Self {
        match err {
            WatermarkError::UnsupportedWatermarkFormat(fmt) => {
                DocumentError::UnsupportedWatermarkFormat(fmt)
            }
            other => DocumentError::WatermarkError(other.to_string()),
        }
    }
}

/// Detects the DocumentFormat based on file extension and MIME type.
pub fn detect_document_format(filename: &str, mime_type: Option<&str>) -> DocumentFormat {
    let lower_filename = filename.to_lowercase();
    let lower_mime = mime_type.unwrap_or("").to_lowercase();

    if lower_filename.ends_with(".txt") || lower_mime == "text/plain" {
        DocumentFormat::PlainText
    } else if lower_filename.ends_with(".md")
        || lower_filename.ends_with(".markdown")
        || lower_mime == "text/markdown"
    {
        DocumentFormat::Utf8Markdown
    } else if lower_filename.ends_with(".pdf") || lower_mime == "application/pdf" {
        DocumentFormat::Pdf
    } else if lower_filename.ends_with(".docx")
        || lower_mime == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    {
        DocumentFormat::Docx
    } else {
        DocumentFormat::Binary
    }
}

/// Ingests a document from actual raw bytes, calculating SHA3-256 over document bytes.
pub fn ingest_document(
    data: &[u8],
    filename: &str,
    mime_type: Option<&str>,
    classification: Classification,
    creator: &str,
) -> Result<IngestedDocument, DocumentError> {
    if data.is_empty() {
        return Err(DocumentError::EmptyDocument);
    }

    // SHA3-256 document hash computed from actual file bytes
    let hash_bytes = hash_document_sha3_256(data);
    let document_hash = hex::encode(hash_bytes);
    let format = detect_document_format(filename, mime_type);
    let determined_mime = match mime_type {
        Some(m) if !m.is_empty() => m.to_string(),
        _ => match format {
            DocumentFormat::PlainText => "text/plain".to_string(),
            DocumentFormat::Utf8Markdown => "text/markdown".to_string(),
            DocumentFormat::Pdf => "application/pdf".to_string(),
            DocumentFormat::Docx => {
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                    .to_string()
            }
            DocumentFormat::Binary => "application/octet-stream".to_string(),
        },
    };

    Ok(IngestedDocument {
        document_id: format!("DOC-{}", Uuid::new_v4()),
        filename: filename.to_string(),
        mime_type: determined_mime,
        file_size: data.len(),
        document_hash,
        classification,
        creator: creator.to_string(),
        creation_timestamp: Utc::now().to_rfc3339(),
        format,
        raw_data: data.to_vec(),
    })
}

const KEK_SALT: &[u8] = b"CRYPTOTRACE-SALT-MLKEM-768-v1";

/// Distributes a document to a list of recipients.
/// Returns the metadata, the AES-GCM encrypted document, the document nonce, and recipient packages.
pub fn distribute_document(
    document_data: &[u8],
    classification: Classification,
    recipients: &[CryptographicIdentityPublic],
) -> Result<(DocumentMetadata, Vec<u8>, Vec<u8>, Vec<RecipientPackage>), DocumentError> {
    // 1. Hash Document
    let hash_bytes = hash_document_sha3_256(document_data);
    let document_hash = hex::encode(hash_bytes);

    // 2. Generate Content Key
    let mut content_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut content_key);

    // 3. Encrypt Document
    let (encrypted_document, doc_nonce) =
        encrypt_document_aes256gcm(&content_key, document_data)
            .map_err(|_| DocumentError::CryptoError("Document encryption failed".to_string()))?;

    // 4. Generate Metadata
    let metadata = DocumentMetadata {
        document_id: format!("DOC-{}", Uuid::new_v4()),
        document_hash: document_hash.clone(),
        classification,
    };

    // 5. Wrap keys for recipients using ML-KEM + HKDF
    let mut packages = Vec::new();
    for recipient in recipients {
        let recipient_pk = kyber768::PublicKey::from_bytes(&recipient.kem_public_key)
            .map_err(|_| DocumentError::CryptoError("Invalid Kem public key".to_string()))?;

        // Encapsulate a shared secret for this recipient
        let (ss, ciphertext) = kyber768::encapsulate(&recipient_pk);

        // Derive KEK from ML-KEM shared secret via HKDF bound to recipient ID and document hash
        let kek = derive_kek_hkdf(
            ss.as_bytes(),
            Some(KEK_SALT),
            &recipient.identity_id,
            &document_hash,
        )
        .map_err(|_| DocumentError::CryptoError("KEK derivation failed".to_string()))?;

        // Encrypt the `content_key` with the derived KEK
        let (encrypted_content_key, wrapped_nonce) = encrypt_document_aes256gcm(&kek, &content_key)
            .map_err(|_| DocumentError::CryptoError("Content key encryption failed".to_string()))?;

        packages.push(RecipientPackage {
            recipient_identity_id: recipient.identity_id.clone(),
            ml_kem_ciphertext: ciphertext.as_bytes().to_vec(),
            encrypted_content_key,
            wrapped_nonce,
        });
    }

    Ok((metadata, encrypted_document, doc_nonce, packages))
}

/// RBAC and Clearance enforced document distribution.
pub fn distribute_document_rbac(
    sender: &User,
    document_data: &[u8],
    classification: Classification,
    recipients: &[User],
) -> Result<(DocumentMetadata, Vec<u8>, Vec<u8>, Vec<RecipientPackage>), DocumentError> {
    // 1. Verify Sender has permission to distribute
    sender
        .role
        .verify_permission(Permission::DistributePackages)?;

    // 2. Validate recipients clearance and active key status
    let mut valid_public_identities = Vec::new();
    for r in recipients {
        // Clearance check
        if !r.clearance_level.can_access(classification) {
            return Err(DocumentError::AuthorizationError(
                AuthError::InsufficientClearance {
                    user_clearance: r.clearance_level.to_string(),
                    required_clearance: classification.to_string(),
                },
            ));
        }

        let identity = r
            .cryptographic_identity
            .as_ref()
            .ok_or(DocumentError::InvalidKey)?;

        if !identity.status.can_operate() {
            return Err(DocumentError::AuthorizationError(AuthError::KeyNotActive {
                status: identity.status.to_string(),
            }));
        }

        valid_public_identities.push(identity.clone());
    }

    distribute_document(document_data, classification, &valid_public_identities)
}

/// Unwraps the symmetric content key using the recipient's ML-KEM secret key.
pub fn unwrap_content_key(
    package: &RecipientPackage,
    document_hash: &str,
    secret_key: &kyber768::SecretKey,
) -> Result<[u8; 32], DocumentError> {
    let ciphertext = kyber768::Ciphertext::from_bytes(&package.ml_kem_ciphertext)
        .map_err(|_| DocumentError::InvalidKey)?;

    // Decapsulate shared secret
    let ss = kyber768::decapsulate(&ciphertext, secret_key);

    // Derive the same KEK using HKDF
    let kek = derive_kek_hkdf(
        ss.as_bytes(),
        Some(KEK_SALT),
        &package.recipient_identity_id,
        document_hash,
    )
    .map_err(|_| DocumentError::CryptoError("KEK derivation failed".to_string()))?;

    // Decrypt content key
    let content_key_vec =
        decrypt_document_aes256gcm(&kek, &package.wrapped_nonce, &package.encrypted_content_key)
            .map_err(|_| DocumentError::DecryptionFailed)?;

    if content_key_vec.len() != 32 {
        return Err(DocumentError::DecryptionFailed);
    }

    let mut content_key = [0u8; 32];
    content_key.copy_from_slice(&content_key_vec);
    Ok(content_key)
}

/// Decrypts the document payload using the recipient's package and ML-KEM secret key.
pub fn decrypt_recipient_document(
    encrypted_document: &[u8],
    doc_nonce: &[u8],
    package: &RecipientPackage,
    document_hash: &str,
    secret_key: &kyber768::SecretKey,
) -> Result<Vec<u8>, DocumentError> {
    let content_key = unwrap_content_key(package, document_hash, secret_key)?;
    let plaintext = decrypt_document_aes256gcm(&content_key, doc_nonce, encrypted_document)
        .map_err(|_| DocumentError::DecryptionFailed)?;
    Ok(plaintext)
}

/// RBAC, clearance, and key-lifecycle enforced document decryption using secure KeyStore abstraction.
pub fn decrypt_recipient_document_rbac(
    recipient: &User,
    keystore: &dyn KeyStore,
    encrypted_document: &[u8],
    doc_nonce: &[u8],
    package: &RecipientPackage,
    doc_metadata: &DocumentMetadata,
) -> Result<Vec<u8>, DocumentError> {
    // 1. Check RBAC permissions
    recipient
        .role
        .verify_permission(Permission::DecryptAuthorizedPackages)?;

    // 2. Check clearance level
    if !recipient
        .clearance_level
        .can_access(doc_metadata.classification)
    {
        return Err(DocumentError::AuthorizationError(
            AuthError::InsufficientClearance {
                user_clearance: recipient.clearance_level.to_string(),
                required_clearance: doc_metadata.classification.to_string(),
            },
        ));
    }

    // 3. Check cryptographic identity
    let identity = recipient
        .cryptographic_identity
        .as_ref()
        .ok_or(DocumentError::InvalidKey)?;

    // 4. Verify recipient is the authorized recipient for this package
    if identity.identity_id != package.recipient_identity_id {
        return Err(DocumentError::AuthorizationError(
            AuthError::RecipientNotAuthorized,
        ));
    }

    // 5. Check key lifecycle status (ACTIVE only)
    if !identity.status.can_operate() {
        return Err(DocumentError::AuthorizationError(AuthError::KeyNotActive {
            status: identity.status.to_string(),
        }));
    }

    // 6. Load protected secret key from KeyStore abstraction
    let protected = keystore
        .load_key(&identity.identity_id)
        .map_err(|e| DocumentError::KeyStoreError(format!("{:?}", e)))?;

    decrypt_recipient_document(
        encrypted_document,
        doc_nonce,
        package,
        &doc_metadata.document_hash,
        &protected.kem_secret,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use identity_core::generate_ml_kem_keypair;

    #[test]
    fn test_distribution_and_decryption_roundtrip() {
        let (pk1, sk1) = generate_ml_kem_keypair();
        let (pk2, sk2) = generate_ml_kem_keypair();

        let recipient1 = CryptographicIdentityPublic {
            identity_id: "RECIPIENT-01".to_string(),
            kem_public_key: pk1.as_bytes().to_vec(),
            dsa_public_key: vec![0u8; 32],
            status: identity_core::KeyStatus::Active,
        };

        let recipient2 = CryptographicIdentityPublic {
            identity_id: "RECIPIENT-02".to_string(),
            kem_public_key: pk2.as_bytes().to_vec(),
            dsa_public_key: vec![0u8; 32],
            status: identity_core::KeyStatus::Active,
        };

        let secret_document = b"TOP SECRET STRATEGIC REPORT - INDIAN ARMED FORCES";
        let recipients = vec![recipient1.clone(), recipient2.clone()];

        let (metadata, enc_doc, doc_nonce, packages) =
            distribute_document(secret_document, Classification::TopSecret, &recipients).unwrap();

        assert_eq!(packages.len(), 2);

        // Recipient 1 decrypts
        let decrypted1 = decrypt_recipient_document(
            &enc_doc,
            &doc_nonce,
            &packages[0],
            &metadata.document_hash,
            &sk1,
        )
        .unwrap();
        assert_eq!(decrypted1, secret_document);

        // Recipient 2 decrypts
        let decrypted2 = decrypt_recipient_document(
            &enc_doc,
            &doc_nonce,
            &packages[1],
            &metadata.document_hash,
            &sk2,
        )
        .unwrap();
        assert_eq!(decrypted2, secret_document);
    }

    #[test]
    fn test_wrong_recipient_key_cannot_decrypt() {
        let (pk1, _) = generate_ml_kem_keypair();
        let (_, sk2) = generate_ml_kem_keypair();

        let recipient1 = CryptographicIdentityPublic {
            identity_id: "RECIPIENT-01".to_string(),
            kem_public_key: pk1.as_bytes().to_vec(),
            dsa_public_key: vec![0u8; 32],
            status: identity_core::KeyStatus::Active,
        };

        let secret_document = b"CONFIDENTIAL DATA";
        let (metadata, enc_doc, doc_nonce, packages) =
            distribute_document(secret_document, Classification::Secret, &[recipient1]).unwrap();

        // Recipient 2 attempts to decrypt Recipient 1's package with sk2
        let result = decrypt_recipient_document(
            &enc_doc,
            &doc_nonce,
            &packages[0],
            &metadata.document_hash,
            &sk2,
        );

        assert!(
            result.is_err(),
            "Recipient 2 must NOT be able to decrypt Recipient 1's package"
        );
    }

    #[test]
    fn test_ingest_document_sha3_changes_with_single_byte() {
        let bytes1 = b"DEFENCE_PLAN_ALPHA: Coordinates 28.6139 N, 77.2090 E";
        let mut bytes2 = bytes1.to_vec();
        bytes2[0] = b'C'; // Change 1 byte: 'D' -> 'C'

        let doc1 = ingest_document(
            bytes1,
            "DEFENCE_PLAN.md",
            Some("text/markdown"),
            Classification::Secret,
            "OFFICER_01",
        )
        .unwrap();

        let doc2 = ingest_document(
            &bytes2,
            "DEFENCE_PLAN.md",
            Some("text/markdown"),
            Classification::Secret,
            "OFFICER_01",
        )
        .unwrap();

        assert_ne!(
            doc1.document_hash, doc2.document_hash,
            "Changing 1 byte must change SHA3-256 document hash"
        );
        assert_eq!(doc1.format, DocumentFormat::Utf8Markdown);
        assert_eq!(doc1.file_size, bytes1.len());
    }

    #[test]
    fn test_format_boundaries_detection() {
        assert_eq!(
            detect_document_format("plan.txt", None),
            DocumentFormat::PlainText
        );
        assert_eq!(
            detect_document_format("plan.md", None),
            DocumentFormat::Utf8Markdown
        );
        assert_eq!(
            detect_document_format("plan.pdf", None),
            DocumentFormat::Pdf
        );
        assert_eq!(
            detect_document_format("plan.docx", None),
            DocumentFormat::Docx
        );
        assert_eq!(
            detect_document_format("plan.bin", None),
            DocumentFormat::Binary
        );
    }
}

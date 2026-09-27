use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
    KeyDerivationFailed,
}

/// Generates a SHA3-256 hash of the input data
pub fn hash_document_sha3_256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Derives a 256-bit Key Encryption Key (KEK) using HKDF-SHA-256 with explicit domain separation,
/// binding to both the recipient context and the document context.
pub fn derive_kek_hkdf(
    shared_secret: &[u8],
    salt: Option<&[u8]>,
    recipient_id: &str,
    document_hash: &str,
) -> Result<[u8; 32], CryptoError> {
    let hk = Hkdf::<Sha256>::new(salt, shared_secret);
    let mut kek = [0u8; 32];
    let info = format!(
        "CRYPTOTRACE-v1|ML-KEM-768-KEK|recipient:{}|doc:{}",
        recipient_id, document_hash
    );
    hk.expand(info.as_bytes(), &mut kek)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(kek)
}

/// Encrypts data using AES-256-GCM.
/// Returns (ciphertext, nonce)
pub fn encrypt_document_aes256gcm(
    key: &[u8; 32],
    data: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok((ciphertext, nonce.to_vec()))
}

/// Decrypts data using AES-256-GCM.
pub fn decrypt_document_aes256gcm(
    key: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256_hashing() {
        let data = b"Classified Document Content";
        let hash = hash_document_sha3_256(data);
        assert_eq!(hash.len(), 32);
        // Deterministic check
        let hash2 = hash_document_sha3_256(data);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_aes256gcm_encryption_decryption_roundtrip() {
        let key = [0x42u8; 32];
        let original_data = b"CONFIDENTIAL INTELLIGENCE BRIEFING: OPERATION TRIDENT";

        let (ciphertext, nonce) = encrypt_document_aes256gcm(&key, original_data).unwrap();
        assert_ne!(ciphertext, original_data);

        let decrypted = decrypt_document_aes256gcm(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_aes256gcm_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let original_data = b"CONFIDENTIAL DATA";

        let (mut ciphertext, nonce) = encrypt_document_aes256gcm(&key, original_data).unwrap();
        // Tamper with ciphertext byte
        ciphertext[0] ^= 0xFF;

        let result = decrypt_document_aes256gcm(&key, &nonce, &ciphertext);
        assert_eq!(result, Err(CryptoError::DecryptionFailed));
    }

    #[test]
    fn test_hkdf_kek_derivation_deterministic() {
        let ss = b"kyber768_shared_secret_bytes_12345";
        let salt = b"cryptotrace_salt_2026";
        let recipient_a = "RECIPIENT-ALPHA-01";
        let doc_hash = "9f2a84b3e8c1d5";

        let kek1 = derive_kek_hkdf(ss, Some(salt), recipient_a, doc_hash).unwrap();
        let kek2 = derive_kek_hkdf(ss, Some(salt), recipient_a, doc_hash).unwrap();
        assert_eq!(
            kek1, kek2,
            "HKDF must be deterministic for identical inputs"
        );
    }

    #[test]
    fn test_hkdf_context_separation_recipient() {
        let ss = b"kyber768_shared_secret_bytes_12345";
        let salt = b"cryptotrace_salt_2026";
        let doc_hash = "9f2a84b3e8c1d5";

        let kek_recipient_a = derive_kek_hkdf(ss, Some(salt), "RECIPIENT-A", doc_hash).unwrap();
        let kek_recipient_b = derive_kek_hkdf(ss, Some(salt), "RECIPIENT-B", doc_hash).unwrap();

        assert_ne!(
            kek_recipient_a, kek_recipient_b,
            "Different recipient contexts MUST produce different KEKs"
        );
    }

    #[test]
    fn test_hkdf_context_separation_document() {
        let ss = b"kyber768_shared_secret_bytes_12345";
        let salt = b"cryptotrace_salt_2026";
        let recipient = "RECIPIENT-A";

        let kek_doc_1 = derive_kek_hkdf(ss, Some(salt), recipient, "DOC-HASH-1").unwrap();
        let kek_doc_2 = derive_kek_hkdf(ss, Some(salt), recipient, "DOC-HASH-2").unwrap();

        assert_ne!(
            kek_doc_1, kek_doc_2,
            "Different document contexts MUST produce different KEKs"
        );
    }
}

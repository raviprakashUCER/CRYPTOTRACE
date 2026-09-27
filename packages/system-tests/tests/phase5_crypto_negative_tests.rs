use crypto_core::{decrypt_document_aes256gcm, derive_kek_hkdf, hash_document_sha3_256};
use document_service::{
    decrypt_recipient_document, distribute_document, unwrap_content_key, Classification,
};
use identity_core::{
    generate_ml_dsa_keypair, generate_ml_kem_keypair, CryptographicIdentityPublic, KeyStatus,
};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::kem::PublicKey as _;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as _};

#[test]
fn test_phase5_cryptographic_negative_paths_fail_closed() {
    let doc_plaintext = b"SECRET DEFENCE ASSETS INVENTORY 2026";
    let doc_hash = hex::encode(hash_document_sha3_256(doc_plaintext));

    // Setup 2 Keypairs (Recipient 1 and Recipient 2)
    let (kem_pk_1, kem_sk_1) = generate_ml_kem_keypair();
    let (dsa_pk_1, dsa_sk_1) = generate_ml_dsa_keypair();

    let (kem_pk_2, kem_sk_2) = generate_ml_kem_keypair();
    let (dsa_pk_2, _dsa_sk_2) = generate_ml_dsa_keypair();

    let id_1 = CryptographicIdentityPublic {
        identity_id: "RECIPIENT-001".to_string(),
        kem_public_key: kem_pk_1.as_bytes().to_vec(),
        dsa_public_key: dsa_pk_1.as_bytes().to_vec(),
        status: KeyStatus::Active,
    };

    let id_2 = CryptographicIdentityPublic {
        identity_id: "RECIPIENT-002".to_string(),
        kem_public_key: kem_pk_2.as_bytes().to_vec(),
        dsa_public_key: dsa_pk_2.as_bytes().to_vec(),
        status: KeyStatus::Active,
    };

    let (_doc_meta, enc_doc, doc_nonce, packages) = distribute_document(
        doc_plaintext,
        Classification::TopSecret,
        &[id_1.clone(), id_2.clone()],
    )
    .unwrap();

    let pkg_1 = packages
        .iter()
        .find(|p| p.recipient_identity_id == id_1.identity_id)
        .unwrap();
    let pkg_2 = packages
        .iter()
        .find(|p| p.recipient_identity_id == id_2.identity_id)
        .unwrap();

    // 1. Recipient 1 successfully unwraps content key with own secret key
    let content_key_1 =
        unwrap_content_key(pkg_1, &doc_hash, &kem_sk_1).expect("Legitimate unwrap must succeed");

    // 2. Wrong ML-KEM secret key fails: Recipient 2 tries to unwrap Recipient 1's package
    let wrong_key_unwrap = unwrap_content_key(pkg_1, &doc_hash, &kem_sk_2);
    assert!(
        wrong_key_unwrap.is_err(),
        "Recipient 2 secret key MUST NOT unwrap Recipient 1's package"
    );

    // 3. Wrong package decryption fails
    let wrong_pkg_decrypt =
        decrypt_recipient_document(&enc_doc, &doc_nonce, pkg_2, &doc_hash, &kem_sk_1);
    assert!(
        wrong_pkg_decrypt.is_err(),
        "Recipient 1 secret key MUST NOT decrypt Recipient 2's package"
    );

    // 4. Modified AES-256-GCM ciphertext fails authentication
    let mut tampered_ciphertext = enc_doc.clone();
    tampered_ciphertext[0] ^= 0x01;
    let tampered_cipher_res =
        decrypt_document_aes256gcm(&content_key_1, &doc_nonce, &tampered_ciphertext);
    assert!(
        tampered_cipher_res.is_err(),
        "Flipping 1 byte of AES ciphertext must fail authentication"
    );

    // 5. Modified AES-256-GCM nonce fails authentication
    let mut tampered_nonce = doc_nonce.clone();
    tampered_nonce[0] ^= 0xFF;
    let tampered_nonce_res = decrypt_document_aes256gcm(&content_key_1, &tampered_nonce, &enc_doc);
    assert!(
        tampered_nonce_res.is_err(),
        "Modifying nonce must fail AES-GCM decryption"
    );

    // 6. Modified ML-KEM ciphertext fails decapsulation / unwrapping
    let mut tampered_pkg = pkg_1.clone();
    tampered_pkg.ml_kem_ciphertext[0] ^= 0xAA;
    let tampered_kem_res = unwrap_content_key(&tampered_pkg, &doc_hash, &kem_sk_1);
    assert!(
        tampered_kem_res.is_err(),
        "Corrupted ML-KEM ciphertext must fail unwrapping"
    );

    // 7. Modified wrapped content key bytes fail AES-GCM unwrapping
    let mut tampered_wrapped_key = pkg_1.clone();
    tampered_wrapped_key.encrypted_content_key[0] ^= 0x55;
    let tampered_wrapped_res = unwrap_content_key(&tampered_wrapped_key, &doc_hash, &kem_sk_1);
    assert!(
        tampered_wrapped_res.is_err(),
        "Corrupted encrypted content key must fail unwrap"
    );

    // 8. ML-DSA signature verification fails on modified message
    let message = b"ATTESTATION_MESSAGE_HASH_EVIDENCE";
    let signature = dilithium3::detached_sign(message, &dsa_sk_1);

    let mut tampered_message = message.to_vec();
    tampered_message[0] ^= 0x01;
    let verify_tampered_msg =
        dilithium3::verify_detached_signature(&signature, &tampered_message, &dsa_pk_1);
    assert!(
        verify_tampered_msg.is_err(),
        "ML-DSA signature on tampered message must fail"
    );

    // 9. ML-DSA signature verification fails with wrong public key
    let verify_wrong_pk = dilithium3::verify_detached_signature(&signature, message, &dsa_pk_2);
    assert!(
        verify_wrong_pk.is_err(),
        "ML-DSA signature verified against wrong recipient PK must fail"
    );

    // 10. Corrupted signature bytes fail verification
    let mut sig_bytes = signature.as_bytes().to_vec();
    sig_bytes[0] ^= 0xFF;
    let corrupted_sig = DetachedSignature::from_bytes(&sig_bytes);
    if let Ok(sig) = corrupted_sig {
        let verify_corrupt = dilithium3::verify_detached_signature(&sig, message, &dsa_pk_1);
        assert!(
            verify_corrupt.is_err(),
            "Corrupted signature bytes must fail"
        );
    }

    // 11. HKDF context separation: changing recipient_id changes KEK
    let ss = [42u8; 32];
    let kek_recip_a = derive_kek_hkdf(&ss, None, "RECIPIENT_A", &doc_hash).unwrap();
    let kek_recip_b = derive_kek_hkdf(&ss, None, "RECIPIENT_B", &doc_hash).unwrap();
    assert_ne!(
        kek_recip_a, kek_recip_b,
        "HKDF must derive different KEKs when recipient ID differs"
    );

    // 12. HKDF context separation: changing document_hash changes KEK
    let kek_doc_1 = derive_kek_hkdf(&ss, None, "RECIPIENT_A", "HASH_DOC_ALPHA").unwrap();
    let kek_doc_2 = derive_kek_hkdf(&ss, None, "RECIPIENT_A", "HASH_DOC_BETA").unwrap();
    assert_ne!(
        kek_doc_1, kek_doc_2,
        "HKDF must derive different KEKs when document hash differs"
    );
}

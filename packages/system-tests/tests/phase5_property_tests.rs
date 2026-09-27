use crypto_core::derive_kek_hkdf;
use forensics_service::ForensicsManager;
use ledger_core::{HashChain, LedgerMerkleTree, Sha3Algorithm};
use proptest::prelude::*;
use rs_merkle::Hasher;
use watermark_core::{decode_zero_width, encode_zero_width, ReedSolomon};

proptest! {
    // 1. Watermark Zero-Width Framing Roundtrip Invariant
    #[test]
    fn prop_test_zero_width_framing_roundtrip(data in proptest::collection::vec(any::<u8>(), 1..64)) {
        let encoded = encode_zero_width(&data);
        let decoded = decode_zero_width(&encoded).expect("Decoding valid zero-width binary must succeed");
        prop_assert_eq!(data, decoded);
    }

    // 2. Event ID Invariant: Always starts with 'EVT-' and is exactly 36 characters long
    #[test]
    fn prop_test_event_id_format_invariant(
        doc_hash in "[0-9a-f]{64}",
        recipient_id in "[A-Za-z0-9_-]{8,32}",
        session_id in "[A-Za-z0-9_-]{4,16}",
        nonce in proptest::collection::vec(any::<u8>(), 12..32)
    ) {
        let event_id = ForensicsManager::generate_event_id(&doc_hash, &recipient_id, &session_id, &nonce);
        prop_assert!(event_id.starts_with("EVT-"));
        prop_assert_eq!(event_id.len(), 36);
        let hex_part = &event_id[4..];
        prop_assert!(hex::decode(hex_part).is_ok());
    }

    // 3. Reed-Solomon Erasure Resilience: Erasing up to N-K parity shards always reconstructs payload
    #[test]
    fn prop_test_reed_solomon_erasure_recovery(
        payload in proptest::collection::vec(any::<u8>(), 8..36),
        erased_count in 0usize..=4usize
    ) {
        let r = ReedSolomon::new(8, 4).unwrap();
        let shard_size = payload.len().div_ceil(8);
        let mut padded = payload.clone();
        padded.resize(shard_size * 8, 0u8);

        let mut shards: Vec<Vec<u8>> = padded.chunks(shard_size).map(|c| c.to_vec()).collect();
        for _ in 0..4 {
            shards.push(vec![0u8; shard_size]);
        }

        r.encode(&mut shards).unwrap();

        let mut corrupted_shards: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        for shard in corrupted_shards.iter_mut().take(erased_count) {
            *shard = None;
        }

        r.reconstruct(&mut corrupted_shards).unwrap();

        let mut reconstructed_bytes = Vec::new();
        for shard in corrupted_shards.iter().take(8) {
            reconstructed_bytes.extend_from_slice(shard.as_ref().unwrap());
        }
        prop_assert_eq!(&padded, &reconstructed_bytes);
    }

    // 4. Ledger HashChain Continuity Invariant
    #[test]
    fn prop_test_ledger_hashchain_continuity(
        payloads in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 10..100), 2..10)
    ) {
        let mut chain = HashChain::new();
        for p in &payloads {
            chain.append(p).expect("Appending block must succeed");
        }

        prop_assert!(chain.verify(), "Sequential hash-chain must verify");
        for i in 1..chain.blocks.len() {
            prop_assert_eq!(&chain.blocks[i].previous_hash, &chain.blocks[i-1].current_hash);
        }
    }

    // 5. Merkle Tree Inclusion Proof Validity Invariant
    #[test]
    fn prop_test_merkle_tree_inclusion_proof_validity(
        leaves in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 16..64), 2..16)
    ) {
        let leaf_hashes: Vec<[u8; 32]> = leaves.iter().map(|l| Sha3Algorithm::hash(l)).collect();
        let tree = LedgerMerkleTree::new(&leaf_hashes);

        for (idx, leaf_hash) in leaf_hashes.iter().enumerate().take(leaves.len()) {
            let proof = tree.generate_inclusion_proof(idx).expect("Proof generation must succeed");
            let valid = LedgerMerkleTree::verify_inclusion(&proof, leaf_hash);
            prop_assert!(valid, "Valid inclusion proof must verify against correct leaf");

            let mut tampered_leaf = *leaf_hash;
            tampered_leaf[0] ^= 0xFF;
            let invalid = LedgerMerkleTree::verify_inclusion(&proof, &tampered_leaf);
            prop_assert!(!invalid, "Proof against tampered leaf must fail");
        }
    }

    // 6. HKDF Context Separation Invariant
    #[test]
    fn prop_test_hkdf_context_separation(
        shared_secret in proptest::collection::vec(any::<u8>(), 32..=32),
        recip_a in "[a-z]{5,10}",
        recip_b in "[A-Z]{5,10}",
        doc_hash in "[0-9a-f]{64}"
    ) {
        let kek_a = derive_kek_hkdf(&shared_secret, None, &recip_a, &doc_hash).unwrap();
        let kek_b = derive_kek_hkdf(&shared_secret, None, &recip_b, &doc_hash).unwrap();
        prop_assert_ne!(kek_a, kek_b);
    }
}

use crypto_core::{
    decrypt_document_aes256gcm, derive_kek_hkdf, encrypt_document_aes256gcm, hash_document_sha3_256,
};
use document_service::{decrypt_recipient_document_rbac, distribute_document_rbac, Classification};
use forensics_service::{AttributionStatus, ForensicsManager};
use identity_core::{
    generate_ml_dsa_keypair, generate_ml_kem_keypair, ClearanceLevel, KeyStatus, Role,
};
use identity_service::IdentityManager;
use ledger_core::{HashChain, LedgerMerkleTree, Sha3Algorithm};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_kyber::kyber768;
use rs_merkle::Hasher;
use std::time::Instant;
use storage_sqlite::SqliteDatabase;
use watermark_core::{DocumentFormat, MultiLayerWatermarkManager, ReedSolomon, WatermarkPayload};

fn measure_stats<F: FnMut()>(mut op: F, iterations: usize) -> (f64, f64, f64, f64) {
    let mut times_us = Vec::with_capacity(iterations);
    // Warmup
    for _ in 0..(iterations / 5).max(1) {
        op();
    }
    for _ in 0..iterations {
        let start = Instant::now();
        op();
        let dur = start.elapsed().as_secs_f64() * 1_000_000.0; // microseconds
        times_us.push(dur);
    }
    times_us.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let avg = times_us.iter().sum::<f64>() / times_us.len() as f64;
    let median = times_us[times_us.len() / 2];
    let min = times_us[0];
    let max = times_us[times_us.len() - 1];
    (avg, median, min, max)
}

#[test]
fn test_phase5_execute_and_print_all_benchmarks() {
    println!("\n==========================================================================================");
    println!("CRYPTOTRACE PHASE 5 PERFORMANCE BENCHMARK EXECUTION");
    println!("==========================================================================================");

    // ------------------------------------------------------------------------
    // 1. Cryptography Primitives
    // ------------------------------------------------------------------------
    println!("\n[1] CRYPTOGRAPHIC PRIMITIVES BENCHMARK (Microseconds)");
    println!(
        "{:<35} | {:<10} | {:<10} | {:<10} | {:<10}",
        "Operation", "Avg (μs)", "Median (μs)", "Min (μs)", "Max (μs)"
    );
    println!("------------------------------------------------------------------------------------------");

    // SHA3-256 Hashing across sizes
    for (size_kb, iters) in [(1, 30), (10, 20), (100, 10), (1024, 5)] {
        let data = vec![0x42u8; size_kb * 1024];
        let (avg, med, min, max) = measure_stats(
            || {
                let _ = hash_document_sha3_256(&data);
            },
            iters,
        );
        let name = format!("SHA3-256 Hashing ({} KB)", size_kb);
        println!(
            "{:<35} | {:<10.2} | {:<10.2} | {:<10.2} | {:<10.2}",
            name, avg, med, min, max
        );
    }

    // AES-256-GCM Encrypt & Decrypt across sizes
    for (size_kb, iters) in [(1, 30), (10, 20), (100, 10), (1024, 5)] {
        let key = [0x55u8; 32];
        let data = vec![0x33u8; size_kb * 1024];
        let (avg, med, min, max) = measure_stats(
            || {
                let _ = encrypt_document_aes256gcm(&key, &data);
            },
            iters,
        );
        let name = format!("AES-256-GCM Encrypt ({} KB)", size_kb);
        println!(
            "{:<35} | {:<10.2} | {:<10.2} | {:<10.2} | {:<10.2}",
            name, avg, med, min, max
        );

        let (enc, nonce) = encrypt_document_aes256gcm(&key, &data).unwrap();
        let (avg_d, med_d, min_d, max_d) = measure_stats(
            || {
                let _ = decrypt_document_aes256gcm(&key, &nonce, &enc);
            },
            iters,
        );
        let name_d = format!("AES-256-GCM Decrypt ({} KB)", size_kb);
        println!(
            "{:<35} | {:<10.2} | {:<10.2} | {:<10.2} | {:<10.2}",
            name_d, avg_d, med_d, min_d, max_d
        );
    }

    // ML-KEM-768 Encapsulation & Decapsulation
    let (kem_pk, kem_sk) = generate_ml_kem_keypair();
    let (avg_ke, med_ke, min_ke, max_ke) = measure_stats(
        || {
            let _ = kyber768::encapsulate(&kem_pk);
        },
        30,
    );
    println!(
        "{:<35} | {:<10.2} | {:<10.2} | {:<10.2} | {:<10.2}",
        "ML-KEM-768 Encapsulation", avg_ke, med_ke, min_ke, max_ke
    );

    let (_, ct) = kyber768::encapsulate(&kem_pk);
    let (avg_kd, med_kd, min_kd, max_kd) = measure_stats(
        || {
            let _ = kyber768::decapsulate(&ct, &kem_sk);
        },
        30,
    );
    println!(
        "{:<35} | {:<10.2} | {:<10.2} | {:<10.2} | {:<10.2}",
        "ML-KEM-768 Decapsulation", avg_kd, med_kd, min_kd, max_kd
    );

    // ML-DSA-65 Signing & Verification
    let (dsa_pk, dsa_sk) = generate_ml_dsa_keypair();
    let msg = b"SAMPLE_ATTESTATION_MESSAGE_FOR_BENCHMARK";
    let (avg_ds, med_ds, min_ds, max_ds) = measure_stats(
        || {
            let _ = dilithium3::detached_sign(msg, &dsa_sk);
        },
        30,
    );
    println!(
        "{:<35} | {:<10.2} | {:<10.2} | {:<10.2} | {:<10.2}",
        "ML-DSA-65 Detached Sign", avg_ds, med_ds, min_ds, max_ds
    );

    let sig = dilithium3::detached_sign(msg, &dsa_sk);
    let (avg_dv, med_dv, min_dv, max_dv) = measure_stats(
        || {
            let _ = dilithium3::verify_detached_signature(&sig, msg, &dsa_pk);
        },
        30,
    );
    println!(
        "{:<35} | {:<10.2} | {:<10.2} | {:<10.2} | {:<10.2}",
        "ML-DSA-65 Signature Verify", avg_dv, med_dv, min_dv, max_dv
    );

    // HKDF KEK Derivation
    let ss = [0x11u8; 32];
    let (avg_hk, med_hk, min_hk, max_hk) = measure_stats(
        || {
            let _ = derive_kek_hkdf(&ss, None, "RECIPIENT_BENCH", "DOC_HASH_BENCH");
        },
        30,
    );
    println!(
        "{:<35} | {:<10.2} | {:<10.2} | {:<10.2} | {:<10.2}",
        "HKDF KEK Derivation", avg_hk, med_hk, min_hk, max_hk
    );

    // ------------------------------------------------------------------------
    // 2. Watermarking Primitives
    // ------------------------------------------------------------------------
    println!("\n[2] WATERMARKING PRIMITIVES BENCHMARK (Microseconds)");
    println!(
        "{:<35} | {:<10} | {:<10} | {:<10} | {:<10}",
        "Operation", "Avg (μs)", "Median (μs)", "Min (μs)", "Max (μs)"
    );
    println!("------------------------------------------------------------------------------------------");

    let event_id = "EVT-11112222333344445555666677778888";
    let text =
        "Strategic defence directive intelligence report 2026.\nClassified operations dispatch.\n";

    // Zero-Width Embed & Extract
    let (avg_ze, med_ze, min_ze, max_ze) = measure_stats(
        || {
            let _ = ForensicsManager::embed_event_watermark(event_id, text);
        },
        30,
    );
    println!(
        "{:<35} | {:<10.2} | {:<10.2} | {:<10.2} | {:<10.2}",
        "ZeroWidth Watermark Embed", avg_ze, med_ze, min_ze, max_ze
    );

    let zw_text = ForensicsManager::embed_event_watermark(event_id, text).unwrap();
    let (avg_zx, med_zx, min_zx, max_zx) = measure_stats(
        || {
            let _ = ForensicsManager::extract_event_id_from_document(&zw_text);
        },
        30,
    );
    println!(
        "{:<35} | {:<10.2} | {:<10.2} | {:<10.2} | {:<10.2}",
        "ZeroWidth Watermark Extract", avg_zx, med_zx, min_zx, max_zx
    );

    // MultiLayer Structural Spacing Embed & Extract
    let manager = MultiLayerWatermarkManager::new();
    let wm_payload = WatermarkPayload::new(event_id.to_string(), "DOC-HASH-123".to_string(), None);
    let (avg_se, med_se, min_se, max_se) = measure_stats(
        || {
            let _ = manager.embed_multi_layer(text, &wm_payload, DocumentFormat::PlainText, 8, 4);
        },
        30,
    );
    println!(
        "{:<35} | {:<10.2} | {:<10.2} | {:<10.2} | {:<10.2}",
        "MultiLayer Structural Embed", avg_se, med_se, min_se, max_se
    );

    let multi_text = manager
        .embed_multi_layer(text, &wm_payload, DocumentFormat::PlainText, 8, 4)
        .unwrap();
    let (avg_sx, med_sx, min_sx, max_sx) = measure_stats(
        || {
            let _ = manager.extract_multi_layer(&multi_text, 8, 4);
        },
        30,
    );
    println!(
        "{:<35} | {:<10.2} | {:<10.2} | {:<10.2} | {:<10.2}",
        "MultiLayer Structural Extract", avg_sx, med_sx, min_sx, max_sx
    );

    // Reed-Solomon (8,4) Split & Reconstruction
    let payload_bytes = event_id.as_bytes();
    let r = ReedSolomon::new(8, 4).unwrap();
    let shard_size = payload_bytes.len().div_ceil(8);
    let mut padded = payload_bytes.to_vec();
    padded.resize(shard_size * 8, 0u8);

    let (avg_rs_e, med_rs_e, min_rs_e, max_rs_e) = measure_stats(
        || {
            let mut shards: Vec<Vec<u8>> = padded.chunks(shard_size).map(|c| c.to_vec()).collect();
            for _ in 0..4 {
                shards.push(vec![0u8; shard_size]);
            }
            let _ = r.encode(&mut shards);
        },
        30,
    );
    println!(
        "{:<35} | {:<10.2} | {:<10.2} | {:<10.2} | {:<10.2}",
        "Reed-Solomon (8,4) Encode", avg_rs_e, med_rs_e, min_rs_e, max_rs_e
    );

    let mut shards: Vec<Vec<u8>> = padded.chunks(shard_size).map(|c| c.to_vec()).collect();
    for _ in 0..4 {
        shards.push(vec![0u8; shard_size]);
    }
    r.encode(&mut shards).unwrap();
    let mut corrupted: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
    corrupted[0] = None;
    corrupted[1] = None;

    let (avg_rs_r, med_rs_r, min_rs_r, max_rs_r) = measure_stats(
        || {
            let mut c = corrupted.clone();
            let _ = r.reconstruct(&mut c);
        },
        30,
    );
    println!(
        "{:<35} | {:<10.2} | {:<10.2} | {:<10.2} | {:<10.2}",
        "Reed-Solomon 2-Erasure Recover", avg_rs_r, med_rs_r, min_rs_r, max_rs_r
    );

    // ------------------------------------------------------------------------
    // 3. Ledger & Merkle Primitives
    // ------------------------------------------------------------------------
    println!("\n[3] LEDGER & MERKLE PRIMITIVES BENCHMARK (Microseconds)");
    println!(
        "{:<35} | {:<10} | {:<10} | {:<10} | {:<10}",
        "Operation", "Avg (μs)", "Median (μs)", "Min (μs)", "Max (μs)"
    );
    println!("------------------------------------------------------------------------------------------");

    let mut chain = HashChain::new();
    let (avg_la, med_la, min_la, max_la) = measure_stats(
        || {
            let _ = chain.append(b"BENCHMARK_LEDGER_BLOCK_PAYLOAD");
        },
        30,
    );
    println!(
        "{:<35} | {:<10.2} | {:<10.2} | {:<10.2} | {:<10.2}",
        "HashChain Block Append", avg_la, med_la, min_la, max_la
    );

    let (avg_lv, med_lv, min_lv, max_lv) = measure_stats(
        || {
            let _ = chain.verify();
        },
        30,
    );
    println!(
        "{:<35} | {:<10.2} | {:<10.2} | {:<10.2} | {:<10.2}",
        "HashChain Verify (30 blocks)", avg_lv, med_lv, min_lv, max_lv
    );

    let leaves: Vec<[u8; 32]> = (0..64)
        .map(|i| Sha3Algorithm::hash(&[i as u8; 32]))
        .collect();
    let (avg_mt, med_mt, min_mt, max_mt) = measure_stats(
        || {
            let _ = LedgerMerkleTree::new(&leaves);
        },
        30,
    );
    println!(
        "{:<35} | {:<10.2} | {:<10.2} | {:<10.2} | {:<10.2}",
        "Merkle Tree Build (64 leaves)", avg_mt, med_mt, min_mt, max_mt
    );

    let tree = LedgerMerkleTree::new(&leaves);
    let (avg_mp, med_mp, min_mp, max_mp) = measure_stats(
        || {
            let _ = tree.generate_inclusion_proof(32);
        },
        30,
    );
    println!(
        "{:<35} | {:<10.2} | {:<10.2} | {:<10.2} | {:<10.2}",
        "Merkle Proof Generation", avg_mp, med_mp, min_mp, max_mp
    );

    let proof = tree.generate_inclusion_proof(32).unwrap();
    let leaf_32 = leaves[32];
    let (avg_mv, med_mv, min_mv, max_mv) = measure_stats(
        || {
            let _ = LedgerMerkleTree::verify_inclusion(&proof, &leaf_32);
        },
        30,
    );
    println!(
        "{:<35} | {:<10.2} | {:<10.2} | {:<10.2} | {:<10.2}",
        "Merkle Proof Verification", avg_mv, med_mv, min_mv, max_mv
    );

    // ------------------------------------------------------------------------
    // 4. SQLite Persistence
    // ------------------------------------------------------------------------
    println!("\n[4] SQLITE PERSISTENCE BENCHMARK (Microseconds)");
    println!(
        "{:<35} | {:<10} | {:<10} | {:<10} | {:<10}",
        "Operation", "Avg (μs)", "Median (μs)", "Min (μs)", "Max (μs)"
    );
    println!("------------------------------------------------------------------------------------------");

    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join(format!("cryptotrace_bench_{}.db", uuid::Uuid::new_v4()));
    let db = SqliteDatabase::open(&db_path).unwrap();
    let mut id_mgr = IdentityManager::with_database(db.clone(), "bench_pass");

    let u = id_mgr.register_user(
        "User B".to_string(),
        "D".to_string(),
        "O".to_string(),
        ClearanceLevel::Secret,
        Role::Recipient,
    );
    let (enrolled, enrolled_keys) = id_mgr.enroll_cryptographic_identity(&u.user_id).unwrap();
    let pub_id = enrolled
        .cryptographic_identity
        .as_ref()
        .unwrap()
        .identity_id
        .clone();

    let (avg_qu, med_qu, min_qu, max_qu) = measure_stats(
        || {
            let _ = db.get_user(&u.user_id);
        },
        30,
    );
    println!(
        "{:<35} | {:<10.2} | {:<10.2} | {:<10.2} | {:<10.2}",
        "SQLite Get User by ID", avg_qu, med_qu, min_qu, max_qu
    );

    let (avg_qi, med_qi, min_qi, max_qi) = measure_stats(
        || {
            let _ = db.get_identity(&pub_id);
        },
        30,
    );
    println!(
        "{:<35} | {:<10.2} | {:<10.2} | {:<10.2} | {:<10.2}",
        "SQLite Get Identity by ID", avg_qi, med_qi, min_qi, max_qi
    );

    // ------------------------------------------------------------------------
    // 5. Multi-Recipient Scalability Benchmark
    // ------------------------------------------------------------------------
    println!("\n[5] MULTI-RECIPIENT SCALABILITY BENCHMARK");
    println!(
        "{:<20} | {:<15} | {:<15} | {:<15}",
        "Recipients", "Distribution (ms)", "Per-Recip KEK (μs)", "Total Packages"
    );
    println!("------------------------------------------------------------------------------------------");

    let sender_user = id_mgr.register_user(
        "Sender".to_string(),
        "D".to_string(),
        "O".to_string(),
        ClearanceLevel::TopSecret,
        Role::Sender,
    );
    let (sender_enrolled, _) = id_mgr
        .enroll_cryptographic_identity(&sender_user.user_id)
        .unwrap();

    for count in [1, 5, 10, 25, 50] {
        let mut recipients = Vec::with_capacity(count);
        for i in 0..count {
            let r = id_mgr.register_user(
                format!("Officer {}", i),
                "Ops".to_string(),
                "MoD".to_string(),
                ClearanceLevel::TopSecret,
                Role::Recipient,
            );
            let (renrolled, _) = id_mgr.enroll_cryptographic_identity(&r.user_id).unwrap();
            recipients.push(renrolled);
        }

        let doc_payload = b"TOP SECRET STRATEGIC BATCH DEPLOYMENT ORDER 2026";
        let start = Instant::now();
        let (_meta, _enc, _nonce, pkgs) = distribute_document_rbac(
            &sender_enrolled,
            doc_payload,
            Classification::TopSecret,
            &recipients,
        )
        .unwrap();
        let total_ms = start.elapsed().as_secs_f64() * 1000.0;
        let per_recip_us = (total_ms * 1000.0) / count as f64;
        println!(
            "{:<20} | {:<15.2} | {:<15.2} | {:<15}",
            count,
            total_ms,
            per_recip_us,
            pkgs.len()
        );
    }

    // ------------------------------------------------------------------------
    // 6. End-to-End Workflow Latency across Document Sizes
    // ------------------------------------------------------------------------
    println!("\n[6] END-TO-END WORKFLOW LATENCY BY DOCUMENT SIZE");
    println!(
        "{:<15} | {:<18} | {:<18} | {:<18}",
        "Doc Size", "Distribution (ms)", "Decryption (ms)", "Forensics (ms)"
    );
    println!("------------------------------------------------------------------------------------------");

    for size_kb in [1, 10, 100, 1024] {
        let doc_payload = vec![0x41u8; size_kb * 1024];
        let recip = vec![enrolled.clone()];

        // Distribute
        let start_dist = Instant::now();
        let (meta, enc, nonce, pkgs) = distribute_document_rbac(
            &sender_enrolled,
            &doc_payload,
            Classification::Secret,
            &recip,
        )
        .unwrap();
        let dist_ms = start_dist.elapsed().as_secs_f64() * 1000.0;

        // Decrypt
        let start_dec = Instant::now();
        let decrypted = decrypt_recipient_document_rbac(
            &enrolled,
            id_mgr.keystore.as_ref().unwrap(),
            &enc,
            &nonce,
            &pkgs[0],
            &meta,
        )
        .unwrap();
        let dec_ms = start_dec.elapsed().as_secs_f64() * 1000.0;

        let dec_text = String::from_utf8(decrypted).unwrap();
        let evt_id =
            ForensicsManager::generate_event_id(&meta.document_hash, &pub_id, "SES-BENCH", &nonce);
        let watermarked = ForensicsManager::embed_event_watermark(&evt_id, &dec_text).unwrap();

        let att = ForensicsManager::generate_attestation(
            evt_id.clone(),
            meta.document_hash.clone(),
            pub_id.clone(),
            "SES-BENCH".to_string(),
            &enrolled_keys.dsa_secret,
        )
        .unwrap();
        let att_payload = bincode::serialize(&att).unwrap();
        let _ = db.append_ledger_block(&evt_id, &meta.document_hash, &pub_id, &att_payload);
        let _ = db.insert_decryption_event(
            &evt_id,
            &meta.document_hash,
            &pub_id,
            "SES-BENCH",
            KeyStatus::Active,
            &att_payload,
            &att.signature,
        );

        // Forensics
        let start_for = Instant::now();
        let rep = ForensicsManager::verify_leaked_document_persistent(
            &watermarked,
            &meta.document_hash,
            &db,
        )
        .unwrap();
        let for_ms = start_for.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(rep.status, AttributionStatus::VerifiedAttribution);

        let size_str = format!("{} KB", size_kb);
        println!(
            "{:<15} | {:<18.2} | {:<18.2} | {:<18.2}",
            size_str, dist_ms, dec_ms, for_ms
        );
    }

    let _ = std::fs::remove_file(&db_path);
    println!("==========================================================================================\n");
}

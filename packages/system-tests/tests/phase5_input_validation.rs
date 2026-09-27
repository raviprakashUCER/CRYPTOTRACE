use document_service::{
    detect_document_format, ingest_document, Classification, DocumentError, DocumentFormat,
};
use forensics_service::{AttributionStatus, ForensicsManager};
use ledger_core::LedgerMerkleTree;
use storage_sqlite::SqliteDatabase;
use watermark_core::{decode_zero_width, WatermarkEnvelope};

#[test]
fn test_phase5_input_validation_and_crash_freedom() {
    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join(format!(
        "cryptotrace_phase5_fuzz_{}.db",
        uuid::Uuid::new_v4()
    ));
    let db = SqliteDatabase::open(&db_path).unwrap();

    // 1. Empty Document Ingestion
    let empty_res = ingest_document(
        b"",
        "empty.txt",
        Some("text/plain"),
        Classification::Public,
        "test_user",
    );
    assert_eq!(empty_res.unwrap_err(), DocumentError::EmptyDocument);

    // 2. Unsupported Formats Detection & Forensic Handling
    assert_eq!(
        detect_document_format("manual.pdf", Some("application/pdf")),
        DocumentFormat::Pdf
    );
    assert_eq!(
        detect_document_format("brief.docx", None),
        DocumentFormat::Docx
    );
    assert_eq!(
        detect_document_format("archive.tar.gz", Some("application/gzip")),
        DocumentFormat::Binary
    );

    let unsupported_pdf_report =
        ForensicsManager::investigate_unsupported_format("classified.pdf", DocumentFormat::Pdf);
    assert_eq!(
        unsupported_pdf_report.watermark_status,
        "UNSUPPORTED_WATERMARK_FORMAT"
    );
    assert_eq!(
        unsupported_pdf_report.status,
        AttributionStatus::InsufficientEvidence
    );

    let unsupported_docx_report =
        ForensicsManager::investigate_unsupported_format("plan.docx", DocumentFormat::Docx);
    assert_eq!(
        unsupported_docx_report.watermark_status,
        "UNSUPPORTED_WATERMARK_FORMAT"
    );

    // 3. Invalid UTF-8 in watermark extraction
    let invalid_utf8 = b"\xFF\xFE\xFD\xFC\xFB\xFA Non-UTF8 Random String";
    let lossy_str = String::from_utf8_lossy(invalid_utf8);
    let extract_invalid_res = ForensicsManager::extract_event_id_from_document(&lossy_str);
    assert!(
        extract_invalid_res.is_err(),
        "Invalid UTF-8 should fail gracefully without panic"
    );

    // 4. Random / Fuzzed Binary Input
    let mut rng_data = [0u8; 512];
    rand::Rng::fill(&mut rand::thread_rng(), &mut rng_data[..]);
    let fuzzed_str = String::from_utf8_lossy(&rng_data);
    let fuzz_report =
        ForensicsManager::verify_leaked_document_persistent(&fuzzed_str, "target_hash_dummy", &db)
            .unwrap();
    assert_eq!(fuzz_report.status, AttributionStatus::InsufficientEvidence);

    // 5. Malformed Zero-Width Frames
    let malformed_zw = "\u{200B}\u{200C}\u{200B}\u{200D}\u{200C}";
    let decoded_zw = decode_zero_width(malformed_zw);
    assert!(
        decoded_zw.is_err(),
        "Truncated zero-width sequence must return error"
    );

    // 6. Malformed Envelope Header / Bad Magic Bytes
    let bad_magic_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03];
    let envelope_bad_magic = bincode::deserialize::<WatermarkEnvelope>(&bad_magic_bytes);
    assert!(
        envelope_bad_magic.is_err(),
        "Bad magic bytes must be rejected"
    );

    // 7. Malformed Envelope Version
    let mut bad_version_bytes = vec![0x43, 0x54, 0x57, 0x4D]; // 'CTWM'
    bad_version_bytes.push(0x99); // Invalid version
    bad_version_bytes.extend_from_slice(&[0u8; 20]);
    let envelope_bad_version = bincode::deserialize::<WatermarkEnvelope>(&bad_version_bytes);
    assert!(
        envelope_bad_version.is_err(),
        "Invalid version must be rejected"
    );

    // 8. Malformed Merkle Proof Verification
    let tree = LedgerMerkleTree::new(&[[0u8; 32]]);
    let proof = tree.generate_inclusion_proof(0).unwrap();
    let mismatched_leaf = [0x99u8; 32];
    assert!(
        !LedgerMerkleTree::verify_inclusion(&proof, &mismatched_leaf),
        "Mismatched leaf must fail Merkle verification"
    );

    // 9. Malformed Event ID Format
    let malformed_id_report = ForensicsManager::verify_leaked_document_persistent(
        "EVT-NOT-VALID-HEX-STRING",
        "doc_hash_123",
        &db,
    )
    .unwrap();
    assert_eq!(
        malformed_id_report.status,
        AttributionStatus::InsufficientEvidence
    );

    // 10. Malformed JSON Serialization Handling
    let json_res = ForensicsManager::generate_forensic_report_json(&unsupported_pdf_report);
    assert!(json_res.is_ok(), "JSON report serialization must succeed");
    assert!(json_res.unwrap().contains("UNSUPPORTED_WATERMARK_FORMAT"));

    let _ = std::fs::remove_file(&db_path);
}

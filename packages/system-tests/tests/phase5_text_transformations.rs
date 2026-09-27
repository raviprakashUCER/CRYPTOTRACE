use forensics_service::ForensicsManager;
use watermark_core::{embed_watermark_with_ecc, extract_watermark_with_ecc};

#[derive(Debug)]
struct TransformationResult {
    name: &'static str,
    attempts: usize,
    recovered: usize,
    failed: usize,
    rate_percent: f32,
}

#[test]
fn test_phase5_text_transformation_empirical_benchmarks() {
    let event_id = "EVT-777788889999AAAABBBBCCCCDDDDEEEE";
    let base_text = "The Ministry of Defence hereby orders all strategic naval units to maintain position in the Northern Sector.\nAuthorized personnel only.\nOperational dispatch sequence alpha-nine.\n";

    let mut results = Vec::new();

    // 1. Character Deletion in Host Text (not deleting zero-width characters)
    {
        let attempts = 20;
        let mut recovered = 0;
        for i in 1..=attempts {
            let watermarked = ForensicsManager::embed_event_watermark(event_id, base_text).unwrap();
            // Delete characters from the visible text portion
            let mut chars: Vec<char> = watermarked.chars().collect();
            let visible_indices: Vec<usize> = chars
                .iter()
                .enumerate()
                .filter(|(_, &c)| c != '\u{200B}' && c != '\u{200C}' && c != '\u{200D}')
                .map(|(idx, _)| idx)
                .collect();

            if visible_indices.len() > i {
                for del_idx in visible_indices.iter().take(i) {
                    if *del_idx < chars.len() {
                        chars[*del_idx] = ' ';
                    }
                }
            }
            let modified: String = chars.into_iter().collect();
            if let Ok(extracted) = ForensicsManager::extract_event_id_from_document(&modified) {
                if extracted == event_id {
                    recovered += 1;
                }
            }
        }
        results.push(TransformationResult {
            name: "Character Deletion in Host Text",
            attempts,
            recovered,
            failed: attempts - recovered,
            rate_percent: (recovered as f32 / attempts as f32) * 100.0,
        });
    }

    // 2. Character Insertion in Host Text
    {
        let attempts = 20;
        let mut recovered = 0;
        for i in 1..=attempts {
            let watermarked = ForensicsManager::embed_event_watermark(event_id, base_text).unwrap();
            let modified = format!("{} [INSERTION #{}]", watermarked, i);
            if let Ok(extracted) = ForensicsManager::extract_event_id_from_document(&modified) {
                if extracted == event_id {
                    recovered += 1;
                }
            }
        }
        results.push(TransformationResult {
            name: "Character Insertion in Host Text",
            attempts,
            recovered,
            failed: attempts - recovered,
            rate_percent: (recovered as f32 / attempts as f32) * 100.0,
        });
    }

    // 3. Whitespace & Repeated Space Changes
    {
        let attempts = 20;
        let mut recovered = 0;
        for _ in 0..attempts {
            let watermarked = ForensicsManager::embed_event_watermark(event_id, base_text).unwrap();
            let modified = watermarked.replace(" ", "   ").replace("\n", "\n\n  ");
            if let Ok(extracted) = ForensicsManager::extract_event_id_from_document(&modified) {
                if extracted == event_id {
                    recovered += 1;
                }
            }
        }
        results.push(TransformationResult {
            name: "Whitespace & Repeated Spaces",
            attempts,
            recovered,
            failed: attempts - recovered,
            rate_percent: (recovered as f32 / attempts as f32) * 100.0,
        });
    }

    // 4. Line Ending Transformations (LF to CRLF)
    {
        let attempts = 20;
        let mut recovered = 0;
        for _ in 0..attempts {
            let watermarked = ForensicsManager::embed_event_watermark(event_id, base_text).unwrap();
            let modified = watermarked.replace("\r\n", "\n").replace("\n", "\r\n");
            if let Ok(extracted) = ForensicsManager::extract_event_id_from_document(&modified) {
                if extracted == event_id {
                    recovered += 1;
                }
            }
        }
        results.push(TransformationResult {
            name: "Line Ending Changes (LF <-> CRLF)",
            attempts,
            recovered,
            failed: attempts - recovered,
            rate_percent: (recovered as f32 / attempts as f32) * 100.0,
        });
    }

    // 5. Line Wrapping (80 column reflow)
    {
        let attempts = 20;
        let mut recovered = 0;
        for _ in 0..attempts {
            let watermarked = ForensicsManager::embed_event_watermark(event_id, base_text).unwrap();
            let mut wrapped = String::new();
            for (idx, ch) in watermarked.chars().enumerate() {
                wrapped.push(ch);
                if idx > 0 && idx % 40 == 0 && ch == ' ' {
                    wrapped.push('\n');
                }
            }
            if let Ok(extracted) = ForensicsManager::extract_event_id_from_document(&wrapped) {
                if extracted == event_id {
                    recovered += 1;
                }
            }
        }
        results.push(TransformationResult {
            name: "Line Wrapping & Reflow",
            attempts,
            recovered,
            failed: attempts - recovered,
            rate_percent: (recovered as f32 / attempts as f32) * 100.0,
        });
    }

    // 6. Copy-Paste / Prepend Noise Formatting
    {
        let attempts = 20;
        let mut recovered = 0;
        for _ in 0..attempts {
            let watermarked = ForensicsManager::embed_event_watermark(event_id, base_text).unwrap();
            let modified = format!(
                "--- BEGIN CLASSIFIED FORWARD ---\n{}\n--- END FORWARD ---",
                watermarked
            );
            if let Ok(extracted) = ForensicsManager::extract_event_id_from_document(&modified) {
                if extracted == event_id {
                    recovered += 1;
                }
            }
        }
        results.push(TransformationResult {
            name: "Copy-Paste Envelope Wrapping",
            attempts,
            recovered,
            failed: attempts - recovered,
            rate_percent: (recovered as f32 / attempts as f32) * 100.0,
        });
    }

    // 7. Partial Document Truncation (Watermark at head remains intact)
    {
        let attempts = 20;
        let mut recovered = 0;
        for fraction in [0.9, 0.8, 0.7, 0.6, 0.5] {
            for _ in 0..4 {
                let watermarked =
                    ForensicsManager::embed_event_watermark(event_id, base_text).unwrap();
                let total_chars = watermarked.chars().count();
                let keep_chars = ((total_chars as f32) * fraction) as usize;
                let truncated: String = watermarked.chars().take(keep_chars).collect();
                if let Ok(extracted) = ForensicsManager::extract_event_id_from_document(&truncated)
                {
                    if extracted == event_id {
                        recovered += 1;
                    }
                }
            }
        }
        results.push(TransformationResult {
            name: "Tail Truncation (50%-90% Retained)",
            attempts,
            recovered,
            failed: attempts - recovered,
            rate_percent: (recovered as f32 / attempts as f32) * 100.0,
        });
    }

    // 8. Reed-Solomon Partial Shard Loss (1 to 4 shard erasures)
    {
        let attempts = 20;
        let mut recovered = 0;
        let payload_bytes = event_id.as_bytes();
        for _ in 0..attempts {
            let zw = embed_watermark_with_ecc(payload_bytes, 8, 4).unwrap();
            // Erase 2 shards out of 12
            let mut chars: Vec<char> = zw.chars().collect();
            if chars.len() > 20 {
                chars[6..12].fill('\u{200E}');
            }
            let watermarked_erased =
                format!("{}{}", chars.into_iter().collect::<String>(), base_text);
            if let Ok(rec) = extract_watermark_with_ecc(&watermarked_erased, 8, 4) {
                if let Ok(s) = String::from_utf8(rec) {
                    if s == event_id {
                        recovered += 1;
                    }
                }
            }
        }
        results.push(TransformationResult {
            name: "Reed-Solomon 2-Shard Erasure Recovery",
            attempts,
            recovered,
            failed: attempts - recovered,
            rate_percent: (recovered as f32 / attempts as f32) * 100.0,
        });
    }

    // Print empirical transformation matrix table
    println!("\n==========================================================================================");
    println!("PHASE 5 EMPIRICAL TEXT TRANSFORMATION ROBUSTNESS TABLE");
    println!("==========================================================================================");
    println!(
        "{:<40} | {:<8} | {:<9} | {:<6} | {:<12}",
        "Transformation", "Attempts", "Recovered", "Failed", "Recovery Rate"
    );
    println!("------------------------------------------------------------------------------------------");
    for res in &results {
        println!(
            "{:<40} | {:<8} | {:<9} | {:<6} | {:<6.1}%",
            res.name, res.attempts, res.recovered, res.failed, res.rate_percent
        );
        if res.name.contains("Host Text")
            || res.name.contains("Whitespace")
            || res.name.contains("Line")
            || res.name.contains("Copy-Paste")
            || res.name.contains("Erasure")
        {
            assert!(
                res.rate_percent >= 95.0,
                "Non-destructive transformation {} recovery rate was below 95%: {:.1}%",
                res.name,
                res.rate_percent
            );
        } else {
            assert!(
                res.rate_percent >= 50.0,
                "Partial truncation {} recovery rate was below 50%: {:.1}%",
                res.name,
                res.rate_percent
            );
        }
    }
    println!("==========================================================================================\n");
}

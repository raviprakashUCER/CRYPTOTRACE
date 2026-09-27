#![allow(
    clippy::type_complexity,
    clippy::manual_div_ceil,
    clippy::chunks_exact_to_as_chunks,
    clippy::manual_is_multiple_of
)]

pub use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DocumentFormat {
    PlainText,
    Utf8Markdown,
    Binary,
    Pdf,
    Docx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WatermarkLayerType {
    ZeroWidthText,
    StructuralSpacing,
    FrequencyDomainStub,
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum WatermarkError {
    #[error("Reed-Solomon encoding failed")]
    EccEncodeError,
    #[error("Reed-Solomon decoding failed")]
    EccDecodeError,
    #[error("Invalid zero-width character stream")]
    InvalidEncoding,
    #[error("Malformed watermark frame")]
    InvalidFrame,
    #[error("Invalid sync magic")]
    InvalidMagic,
    #[error("Unsupported watermark version {0}")]
    UnsupportedVersion(u8),
    #[error("Invalid shard configuration")]
    InvalidShardConfig,
    #[error("Payload too large")]
    PayloadTooLarge,
    #[error("Unrecoverable data loss ({0} shards missing, max recoverable is {1})")]
    UnrecoverableLoss(usize, usize),
    #[error("Watermark checksum mismatch")]
    ChecksumMismatch,
    #[error("Insufficient watermark evidence in document")]
    InsufficientWatermarkEvidence,
    #[error("Unsupported watermark format: {0:?}")]
    UnsupportedWatermarkFormat(DocumentFormat),
    #[error("Serialization error")]
    SerializationError,
}

const ZW_ZERO: char = '\u{200B}'; // Zero-Width Space (Bit 0)
const ZW_ONE: char = '\u{200C}'; // Zero-Width Non-Joiner (Bit 1)

pub const FRAME_MAGIC: [u8; 2] = [0x57, 0x4D]; // "WM"
pub const SHARD_MAGIC: [u8; 2] = [0x53, 0x48]; // "SH"
pub const CURRENT_VERSION: u8 = 1;
pub const FRAME_HEADER_LEN: usize = 7; // Magic(2) + Version(1) + DataShards(1) + ParityShards(1) + PayloadLen(2)
pub const CHECKSUM_LEN: usize = 4; // CRC32 (4B)
pub const SHARD_HEADER_LEN: usize = 7; // ShardMagic(2) + Version(1) + ShardIndex(1) + TotalShards(1) + ShardLen(2)

/// Versioned, structured watermark payload containing provenance metadata
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatermarkPayload {
    pub version: u8,
    pub event_id: String,
    pub document_hash: String,
    pub session_id: Option<String>,
    pub created_at_epoch: u64,
}

impl WatermarkPayload {
    pub fn new(event_id: String, document_hash: String, session_id: Option<String>) -> Self {
        Self {
            version: CURRENT_VERSION,
            event_id,
            document_hash,
            session_id,
            created_at_epoch: 0,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, WatermarkError> {
        bincode::serialize(self).map_err(|_| WatermarkError::SerializationError)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WatermarkError> {
        bincode::deserialize(bytes).map_err(|_| WatermarkError::InvalidFrame)
    }
}

/// Metadata envelope describing embedded watermark properties
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WatermarkEnvelope {
    pub version: u8,
    pub layers: Vec<WatermarkLayerType>,
    pub payload: WatermarkPayload,
    pub redundancy_ratio: f32,
    pub total_shards: usize,
    pub data_shards: usize,
    pub parity_shards: usize,
}

/// Extraction metrics for forensic evaluation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtractedWatermark {
    pub payload: WatermarkPayload,
    pub shards_total: usize,
    pub shards_recovered: usize,
    pub shards_erased: usize,
    pub recovery_rate_percent: f32,
    pub layer: WatermarkLayerType,
}

/// Trait defining a pluggable multi-channel watermark engine
pub trait WatermarkEngine {
    fn layer_type(&self) -> WatermarkLayerType;
    fn supports_format(&self, format: DocumentFormat) -> bool;
    fn embed(
        &self,
        document: &str,
        payload: &WatermarkPayload,
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<String, WatermarkError>;
    fn extract(
        &self,
        document: &str,
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<ExtractedWatermark, WatermarkError>;
}

/// Encodes binary data into a string of zero-width characters.
pub fn encode_zero_width(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len() * 8);
    for &byte in data {
        for i in (0..8).rev() {
            if (byte >> i) & 1 == 1 {
                result.push(ZW_ONE);
            } else {
                result.push(ZW_ZERO);
            }
        }
    }
    result
}

/// Decodes a string of zero-width characters back into binary data.
pub fn decode_zero_width(text: &str) -> Result<Vec<u8>, WatermarkError> {
    let zw_chars: Vec<char> = text
        .chars()
        .filter(|&c| c == ZW_ZERO || c == ZW_ONE)
        .collect();

    if zw_chars.is_empty() {
        return Err(WatermarkError::InsufficientWatermarkEvidence);
    }
    if zw_chars.len() % 8 != 0 {
        return Err(WatermarkError::InvalidEncoding);
    }

    let mut data = Vec::with_capacity(zw_chars.len() / 8);
    for chunk in zw_chars.chunks(8) {
        let mut byte = 0u8;
        for (i, &c) in chunk.iter().enumerate() {
            if c == ZW_ONE {
                byte |= 1 << (7 - i);
            }
        }
        data.push(byte);
    }

    Ok(data)
}

/// Frames a payload with sync markers, headers, and CRC32 checksum.
pub fn create_framed_payload(
    payload: &[u8],
    data_shards: usize,
    parity_shards: usize,
) -> Result<Vec<u8>, WatermarkError> {
    if payload.len() > u16::MAX as usize {
        return Err(WatermarkError::PayloadTooLarge);
    }
    if data_shards == 0 || parity_shards == 0 || data_shards + parity_shards > 256 {
        return Err(WatermarkError::InvalidShardConfig);
    }

    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len() + CHECKSUM_LEN);
    frame.extend_from_slice(&FRAME_MAGIC);
    frame.push(CURRENT_VERSION);
    frame.push(data_shards as u8);
    frame.push(parity_shards as u8);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);

    let crc = crc32fast::hash(&frame);
    frame.extend_from_slice(&crc.to_be_bytes());

    Ok(frame)
}

/// Packages a single shard into a tagged fragment with CRC32 for distributed placement.
pub fn create_tagged_shard(
    shard_index: usize,
    total_shards: usize,
    shard_data: &[u8],
) -> Result<Vec<u8>, WatermarkError> {
    if shard_data.len() > u16::MAX as usize || shard_index >= total_shards || total_shards > 256 {
        return Err(WatermarkError::InvalidShardConfig);
    }

    let mut tagged = Vec::with_capacity(SHARD_HEADER_LEN + shard_data.len() + CHECKSUM_LEN);
    tagged.extend_from_slice(&SHARD_MAGIC);
    tagged.push(CURRENT_VERSION);
    tagged.push(shard_index as u8);
    tagged.push(total_shards as u8);
    tagged.extend_from_slice(&(shard_data.len() as u16).to_be_bytes());
    tagged.extend_from_slice(shard_data);

    let crc = crc32fast::hash(&tagged);
    tagged.extend_from_slice(&crc.to_be_bytes());

    Ok(tagged)
}

/// Scans raw bytes for synchronization markers and collects valid tagged shard fragments.
pub fn scan_and_collect_shards(
    raw_bytes: &[u8],
    data_shards: usize,
    parity_shards: usize,
) -> Result<(Vec<Option<Vec<u8>>>, usize), WatermarkError> {
    let total_shards = data_shards + parity_shards;
    if total_shards == 0 || total_shards > 256 {
        return Err(WatermarkError::InvalidShardConfig);
    }

    let mut recovered_map: HashMap<usize, Vec<u8>> = HashMap::new();
    let mut expected_shard_size: Option<usize> = None;

    let mut cursor = 0;
    while cursor + SHARD_HEADER_LEN + CHECKSUM_LEN <= raw_bytes.len() {
        if raw_bytes[cursor..cursor + 2] == SHARD_MAGIC {
            let version = raw_bytes[cursor + 2];
            let shard_idx = raw_bytes[cursor + 3] as usize;
            let frags_total = raw_bytes[cursor + 4] as usize;
            let shard_len =
                u16::from_be_bytes([raw_bytes[cursor + 5], raw_bytes[cursor + 6]]) as usize;

            let total_frag_len = SHARD_HEADER_LEN + shard_len + CHECKSUM_LEN;
            if cursor + total_frag_len <= raw_bytes.len() {
                let frag_bytes = &raw_bytes[cursor..cursor + total_frag_len];
                let payload_and_header = &frag_bytes[..SHARD_HEADER_LEN + shard_len];
                let expected_crc = u32::from_be_bytes([
                    frag_bytes[SHARD_HEADER_LEN + shard_len],
                    frag_bytes[SHARD_HEADER_LEN + shard_len + 1],
                    frag_bytes[SHARD_HEADER_LEN + shard_len + 2],
                    frag_bytes[SHARD_HEADER_LEN + shard_len + 3],
                ]);

                let actual_crc = crc32fast::hash(payload_and_header);
                if actual_crc == expected_crc
                    && version == CURRENT_VERSION
                    && frags_total == total_shards
                    && shard_idx < total_shards
                {
                    let shard_data = &payload_and_header[SHARD_HEADER_LEN..];
                    if let Some(size) = expected_shard_size {
                        if size == shard_data.len() {
                            recovered_map
                                .entry(shard_idx)
                                .or_insert(shard_data.to_vec());
                        }
                    } else {
                        expected_shard_size = Some(shard_data.len());
                        recovered_map
                            .entry(shard_idx)
                            .or_insert(shard_data.to_vec());
                    }
                    cursor += total_frag_len;
                    continue;
                }
            }
        }
        cursor += 1;
    }

    let recovered_count = recovered_map.len();
    if recovered_count == 0 {
        return Err(WatermarkError::InsufficientWatermarkEvidence);
    }

    let mut shards = Vec::with_capacity(total_shards);
    for i in 0..total_shards {
        shards.push(recovered_map.remove(&i));
    }

    Ok((shards, recovered_count))
}

/// Encodes an arbitrary-length payload using dynamic Reed-Solomon shard sizing and zero-width characters.
pub fn embed_watermark_with_ecc(
    payload: &[u8],
    data_shards: usize,
    parity_shards: usize,
) -> Result<String, WatermarkError> {
    let framed = create_framed_payload(payload, data_shards, parity_shards)?;
    let rs =
        ReedSolomon::new(data_shards, parity_shards).map_err(|_| WatermarkError::EccEncodeError)?;

    let shard_size = (framed.len() + data_shards - 1) / data_shards;
    let shard_size = shard_size.max(1);

    let total_data_len = data_shards * shard_size;
    let mut padded_data = framed;
    padded_data.resize(total_data_len, 0u8);

    let total_shards = data_shards + parity_shards;
    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(total_shards);
    for chunk in padded_data.chunks(shard_size) {
        shards.push(chunk.to_vec());
    }
    for _ in 0..parity_shards {
        shards.push(vec![0u8; shard_size]);
    }

    rs.encode(&mut shards)
        .map_err(|_| WatermarkError::EccEncodeError)?;

    // Wrap each shard in a tagged fragment with CRC32 for synchronization
    let mut all_tagged_fragments = Vec::new();
    for (i, shard) in shards.iter().enumerate() {
        let tagged = create_tagged_shard(i, total_shards, shard)?;
        all_tagged_fragments.extend_from_slice(&tagged);
    }

    Ok(encode_zero_width(&all_tagged_fragments))
}

/// Scans zero-width text across all 8 bit alignments to locate and collect valid tagged shards.
pub fn scan_zero_width_text(
    text: &str,
    data_shards: usize,
    parity_shards: usize,
) -> Result<(Vec<Option<Vec<u8>>>, usize), WatermarkError> {
    let zw_chars: Vec<char> = text
        .chars()
        .filter(|&c| c == ZW_ZERO || c == ZW_ONE)
        .collect();

    if zw_chars.is_empty() {
        return Err(WatermarkError::InsufficientWatermarkEvidence);
    }

    let total_shards = data_shards + parity_shards;
    let mut best_shards: Vec<Option<Vec<u8>>> = vec![None; total_shards];
    let mut max_recovered = 0;

    // Scan across all 8 possible bit alignments to tolerate leading bit-level shifts
    for bit_offset in 0..8 {
        if bit_offset >= zw_chars.len() {
            break;
        }
        let slice = &zw_chars[bit_offset..];
        let mut raw_bytes = Vec::with_capacity(slice.len() / 8);
        for chunk in slice.chunks_exact(8) {
            let mut byte = 0u8;
            for (i, &c) in chunk.iter().enumerate() {
                if c == ZW_ONE {
                    byte |= 1 << (7 - i);
                }
            }
            raw_bytes.push(byte);
        }

        if let Ok((shards, count)) = scan_and_collect_shards(&raw_bytes, data_shards, parity_shards)
        {
            if count > max_recovered {
                max_recovered = count;
                best_shards = shards;
                if max_recovered >= data_shards {
                    break;
                }
            }
        }
    }

    if max_recovered == 0 {
        return Err(WatermarkError::InsufficientWatermarkEvidence);
    }

    Ok((best_shards, max_recovered))
}

/// Extracts an arbitrary-length payload with Reed-Solomon error correction from zero-width characters.
pub fn extract_watermark_with_ecc(
    text: &str,
    data_shards: usize,
    parity_shards: usize,
) -> Result<Vec<u8>, WatermarkError> {
    let (shards, _recovered_count) = scan_zero_width_text(text, data_shards, parity_shards)?;
    reconstruct_from_shards(shards, data_shards, parity_shards)
}

/// Reconstructs a payload from shards where some shards may be missing (None).
pub fn reconstruct_from_shards(
    mut shards: Vec<Option<Vec<u8>>>,
    data_shards: usize,
    parity_shards: usize,
) -> Result<Vec<u8>, WatermarkError> {
    let total_shards = data_shards + parity_shards;
    if shards.len() != total_shards {
        return Err(WatermarkError::InvalidShardConfig);
    }

    let missing_count = shards.iter().filter(|s| s.is_none()).count();
    if missing_count > parity_shards {
        return Err(WatermarkError::UnrecoverableLoss(
            missing_count,
            parity_shards,
        ));
    }

    let rs =
        ReedSolomon::new(data_shards, parity_shards).map_err(|_| WatermarkError::EccDecodeError)?;

    rs.reconstruct(&mut shards)
        .map_err(|_| WatermarkError::EccDecodeError)?;

    parse_shards_into_payload(&shards, data_shards)
}

fn parse_shards_into_payload(
    shards: &[Option<Vec<u8>>],
    data_shards: usize,
) -> Result<Vec<u8>, WatermarkError> {
    let mut data_bytes = Vec::new();
    for shard_opt in shards.iter().take(data_shards) {
        match shard_opt {
            Some(shard) => data_bytes.extend_from_slice(shard),
            None => return Err(WatermarkError::EccDecodeError),
        }
    }

    if data_bytes.len() < FRAME_HEADER_LEN + CHECKSUM_LEN {
        return Err(WatermarkError::InvalidFrame);
    }

    if data_bytes[0..2] != FRAME_MAGIC {
        return Err(WatermarkError::InvalidMagic);
    }

    if data_bytes[2] != CURRENT_VERSION {
        return Err(WatermarkError::UnsupportedVersion(data_bytes[2]));
    }

    let payload_len = u16::from_be_bytes([data_bytes[5], data_bytes[6]]) as usize;
    let total_framed_len = FRAME_HEADER_LEN + payload_len;

    if total_framed_len + CHECKSUM_LEN > data_bytes.len() {
        return Err(WatermarkError::InvalidFrame);
    }

    let framed_body = &data_bytes[..total_framed_len];
    let expected_crc = u32::from_be_bytes([
        data_bytes[total_framed_len],
        data_bytes[total_framed_len + 1],
        data_bytes[total_framed_len + 2],
        data_bytes[total_framed_len + 3],
    ]);

    let actual_crc = crc32fast::hash(framed_body);
    if actual_crc != expected_crc {
        return Err(WatermarkError::ChecksumMismatch);
    }

    Ok(data_bytes[FRAME_HEADER_LEN..total_framed_len].to_vec())
}

// ---------------------------------------------------------------------------
// Multi-Layer Watermark Engine Implementations
// ---------------------------------------------------------------------------

/// Layer A: Zero-Width Text Watermark Engine (Distributed & Redundant)
pub struct ZeroWidthEngine;

impl WatermarkEngine for ZeroWidthEngine {
    fn layer_type(&self) -> WatermarkLayerType {
        WatermarkLayerType::ZeroWidthText
    }

    fn supports_format(&self, format: DocumentFormat) -> bool {
        matches!(
            format,
            DocumentFormat::PlainText | DocumentFormat::Utf8Markdown
        )
    }

    fn embed(
        &self,
        document: &str,
        payload: &WatermarkPayload,
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<String, WatermarkError> {
        let payload_bytes = payload.to_bytes()?;
        let zw_watermark = embed_watermark_with_ecc(&payload_bytes, data_shards, parity_shards)?;

        // Deterministic distributed placement across paragraph boundaries
        let paragraphs: Vec<&str> = document.split("\n\n").collect();
        if paragraphs.len() <= 1 {
            Ok(format!("{}{}", zw_watermark, document))
        } else {
            let mut result = String::new();
            let zw_chars: Vec<char> = zw_watermark.chars().collect();
            let chunk_size = (zw_chars.len() + paragraphs.len() - 1) / paragraphs.len();

            for (i, para) in paragraphs.iter().enumerate() {
                if i > 0 {
                    result.push_str("\n\n");
                }
                let start = (i * chunk_size).min(zw_chars.len());
                let end = ((i + 1) * chunk_size).min(zw_chars.len());
                if start < end {
                    let sub_zw: String = zw_chars[start..end].iter().collect();
                    result.push_str(&sub_zw);
                }
                result.push_str(para);
            }
            Ok(result)
        }
    }

    fn extract(
        &self,
        document: &str,
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<ExtractedWatermark, WatermarkError> {
        let total_shards = data_shards + parity_shards;
        let (shards, recovered_count) = scan_zero_width_text(document, data_shards, parity_shards)?;

        let recovered_payload_bytes = reconstruct_from_shards(shards, data_shards, parity_shards)?;
        let payload = WatermarkPayload::from_bytes(&recovered_payload_bytes)?;

        let erased = total_shards.saturating_sub(recovered_count);
        let rate = (recovered_count as f32 / total_shards as f32) * 100.0;

        Ok(ExtractedWatermark {
            payload,
            shards_total: total_shards,
            shards_recovered: recovered_count,
            shards_erased: erased,
            recovery_rate_percent: rate,
            layer: WatermarkLayerType::ZeroWidthText,
        })
    }
}

/// Layer B: Structural / Whitespace Formatting Watermark Engine
pub struct StructuralSpacingEngine;

impl WatermarkEngine for StructuralSpacingEngine {
    fn layer_type(&self) -> WatermarkLayerType {
        WatermarkLayerType::StructuralSpacing
    }

    fn supports_format(&self, format: DocumentFormat) -> bool {
        matches!(
            format,
            DocumentFormat::PlainText | DocumentFormat::Utf8Markdown
        )
    }

    fn embed(
        &self,
        document: &str,
        _payload: &WatermarkPayload,
        _data_shards: usize,
        _parity_shards: usize,
    ) -> Result<String, WatermarkError> {
        // Embeds deterministic structural markers (trailing space pattern on non-empty lines)
        let mut lines = Vec::new();
        for line in document.lines() {
            if !line.is_empty() {
                lines.push(format!("{} ", line.trim_end()));
            } else {
                lines.push(line.to_string());
            }
        }
        Ok(lines.join("\n"))
    }

    fn extract(
        &self,
        document: &str,
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<ExtractedWatermark, WatermarkError> {
        let total_shards = data_shards + parity_shards;
        let structural_lines_count = document
            .lines()
            .filter(|l| l.ends_with(' ') || l.ends_with("\t"))
            .count();

        if structural_lines_count == 0 {
            return Err(WatermarkError::InsufficientWatermarkEvidence);
        }

        // Structural layer acts as secondary anchor verification
        Ok(ExtractedWatermark {
            payload: WatermarkPayload::new(String::new(), String::new(), None),
            shards_total: total_shards,
            shards_recovered: structural_lines_count.min(total_shards),
            shards_erased: total_shards.saturating_sub(structural_lines_count.min(total_shards)),
            recovery_rate_percent: 100.0,
            layer: WatermarkLayerType::StructuralSpacing,
        })
    }
}

/// Layer C: Frequency Domain Stub Engine for Future DWT/DCT Implementation
pub struct FrequencyDomainStubEngine;

impl WatermarkEngine for FrequencyDomainStubEngine {
    fn layer_type(&self) -> WatermarkLayerType {
        WatermarkLayerType::FrequencyDomainStub
    }

    fn supports_format(&self, format: DocumentFormat) -> bool {
        matches!(
            format,
            DocumentFormat::Binary | DocumentFormat::Pdf | DocumentFormat::Docx
        )
    }

    fn embed(
        &self,
        _document: &str,
        _payload: &WatermarkPayload,
        _data_shards: usize,
        _parity_shards: usize,
    ) -> Result<String, WatermarkError> {
        Err(WatermarkError::UnsupportedWatermarkFormat(
            DocumentFormat::Pdf,
        ))
    }

    fn extract(
        &self,
        _document: &str,
        _data_shards: usize,
        _parity_shards: usize,
    ) -> Result<ExtractedWatermark, WatermarkError> {
        Err(WatermarkError::UnsupportedWatermarkFormat(
            DocumentFormat::Pdf,
        ))
    }
}

/// Multi-layer watermark coordinator managing detection, embedding, and cross-channel recovery
pub struct MultiLayerWatermarkManager {
    pub zero_width: ZeroWidthEngine,
    pub structural: StructuralSpacingEngine,
    pub frequency_stub: FrequencyDomainStubEngine,
}

impl Default for MultiLayerWatermarkManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiLayerWatermarkManager {
    pub fn new() -> Self {
        Self {
            zero_width: ZeroWidthEngine,
            structural: StructuralSpacingEngine,
            frequency_stub: FrequencyDomainStubEngine,
        }
    }

    pub fn embed_multi_layer(
        &self,
        document: &str,
        payload: &WatermarkPayload,
        format: DocumentFormat,
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<String, WatermarkError> {
        match format {
            DocumentFormat::PlainText | DocumentFormat::Utf8Markdown => {
                let with_structural =
                    self.structural
                        .embed(document, payload, data_shards, parity_shards)?;
                self.zero_width
                    .embed(&with_structural, payload, data_shards, parity_shards)
            }
            other => Err(WatermarkError::UnsupportedWatermarkFormat(other)),
        }
    }

    pub fn extract_multi_layer(
        &self,
        document: &str,
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<(ExtractedWatermark, Vec<WatermarkLayerType>), WatermarkError> {
        let mut detected_layers = Vec::new();

        // 1. Check Layer B (Structural)
        if self
            .structural
            .extract(document, data_shards, parity_shards)
            .is_ok()
        {
            detected_layers.push(WatermarkLayerType::StructuralSpacing);
        }

        // 2. Extract Layer A (Primary Cryptographic Zero-Width)
        match self
            .zero_width
            .extract(document, data_shards, parity_shards)
        {
            Ok(extracted) => {
                detected_layers.push(WatermarkLayerType::ZeroWidthText);
                Ok((extracted, detected_layers))
            }
            Err(e) => {
                if !detected_layers.is_empty() {
                    Err(WatermarkError::InsufficientWatermarkEvidence)
                } else {
                    Err(e)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_payload_roundtrip() {
        let payload = b"ABC";
        let encoded = embed_watermark_with_ecc(payload, 4, 2).unwrap();
        let extracted = extract_watermark_with_ecc(&encoded, 4, 2).unwrap();
        assert_eq!(extracted, payload);
    }

    #[test]
    fn test_exact_36_byte_event_id_roundtrip() {
        let event_id = b"EVT-9f8e7d6c5b4a3928170f1e2d3c4b5a69";
        assert_eq!(event_id.len(), 36);

        let encoded = embed_watermark_with_ecc(event_id, 8, 4).unwrap();
        let extracted = extract_watermark_with_ecc(&encoded, 8, 4).unwrap();
        assert_eq!(
            extracted, event_id,
            "36-byte Event ID must be recovered exactly without truncation"
        );
    }

    #[test]
    fn test_long_payload_roundtrip() {
        let long_payload = b"GOVERNMENT OF INDIA - CONFIDENTIAL NATIONAL SECURITY ADVISORY - CLASSIFICATION TOP SECRET - SESSION 9823741";
        let encoded = embed_watermark_with_ecc(long_payload, 16, 8).unwrap();
        let extracted = extract_watermark_with_ecc(&encoded, 16, 8).unwrap();
        assert_eq!(extracted, long_payload);
    }

    #[test]
    fn test_reconstruct_with_missing_erased_shards() {
        let event_id = b"EVT-36_BYTE_EVENT_ID_FOR_ATTRIBUTION";
        let data_shards = 8;
        let parity_shards = 4;

        let framed = create_framed_payload(event_id, data_shards, parity_shards).unwrap();
        let rs = ReedSolomon::new(data_shards, parity_shards).unwrap();

        let shard_size = (framed.len() + data_shards - 1) / data_shards;
        let total_data_len = data_shards * shard_size;
        let mut padded = framed;
        padded.resize(total_data_len, 0);

        let mut shards: Vec<Vec<u8>> = padded.chunks(shard_size).map(|c| c.to_vec()).collect();
        for _ in 0..parity_shards {
            shards.push(vec![0u8; shard_size]);
        }
        rs.encode(&mut shards).unwrap();

        let mut optional_shards: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        // Erase 4 shards (equal to parity limit)
        optional_shards[1] = None;
        optional_shards[3] = None;
        optional_shards[5] = None;
        optional_shards[7] = None;

        let recovered =
            reconstruct_from_shards(optional_shards, data_shards, parity_shards).unwrap();
        assert_eq!(
            recovered, event_id,
            "Reed-Solomon must reconstruct original Event ID even with 4 missing shards"
        );
    }

    #[test]
    fn test_unrecoverable_erasure_returns_error() {
        let _event_id = b"EVT-CONFIDENTIAL-ID";
        let data_shards = 4;
        let parity_shards = 2;

        let mut optional_shards: Vec<Option<Vec<u8>>> = vec![Some(vec![1, 2, 3]); 6];
        // Erase 3 shards when parity is only 2
        optional_shards[0] = None;
        optional_shards[1] = None;
        optional_shards[2] = None;

        let result = reconstruct_from_shards(optional_shards, data_shards, parity_shards);
        assert!(matches!(
            result,
            Err(WatermarkError::UnrecoverableLoss(3, 2))
        ));
    }

    #[test]
    fn test_malformed_frame_rejected() {
        let bad_frame = vec![
            0x00, 0x00, 0x01, 0x04, 0x02, 0x00, 0x05, 1, 2, 3, 4, 5, 0, 0, 0, 0,
        ];
        let shards = vec![
            Some(bad_frame[0..4].to_vec()),
            Some(bad_frame[4..8].to_vec()),
            Some(bad_frame[8..12].to_vec()),
            Some(bad_frame[12..16].to_vec()),
            Some(vec![0; 4]),
            Some(vec![0; 4]),
        ];
        let result = reconstruct_from_shards(shards, 4, 2);
        assert!(result.is_err(), "Invalid magic/CRC must be rejected");
    }

    #[test]
    fn test_invalid_zero_width_chars_rejected_without_panic() {
        let text_with_odd_zw = "\u{200B}\u{200C}\u{200B}";
        let res = decode_zero_width(text_with_odd_zw);
        assert!(res.is_err());
    }

    // Step 2.1 & 2.2 additional tests
    #[test]
    fn test_structured_payload_roundtrip() {
        let payload = WatermarkPayload::new(
            "EVT-9f8e7d6c5b4a3928170f1e2d3c4b5a69".to_string(),
            "sha3_doc_hash_1234567890abcdef".to_string(),
            Some("SES-2026-ALPHA".to_string()),
        );

        let engine = ZeroWidthEngine;
        let document = "Paragraph 1: Top secret intelligence brief.\n\nParagraph 2: Strategic deployment plan.";
        let embedded = engine.embed(document, &payload, 8, 4).unwrap();
        assert!(embedded.contains("Top secret"));

        let extracted = engine.extract(&embedded, 8, 4).unwrap();
        assert_eq!(extracted.payload.event_id, payload.event_id);
        assert_eq!(extracted.payload.document_hash, payload.document_hash);
        assert_eq!(extracted.payload.session_id, payload.session_id);
        assert_eq!(extracted.shards_total, 12);
        assert_eq!(extracted.shards_recovered, 12);
        assert_eq!(extracted.shards_erased, 0);
        assert_eq!(extracted.recovery_rate_percent, 100.0);
    }

    #[test]
    fn test_leading_and_trailing_corruption_tolerance() {
        let payload = WatermarkPayload::new(
            "EVT-9f8e7d6c5b4a3928170f1e2d3c4b5a69".to_string(),
            "sha3_doc_hash_1234567890abcdef".to_string(),
            None,
        );

        let engine = ZeroWidthEngine;
        let embedded = engine.embed("Secret directive", &payload, 8, 4).unwrap();

        // Inject leading and trailing garbage zero-width characters
        let corrupted = format!(
            "\u{200B}\u{200B}\u{200C}\u{200C}{}\u{200C}\u{200B}\u{200B}\u{200C}",
            embedded
        );

        let extracted = engine.extract(&corrupted, 8, 4).unwrap();
        assert_eq!(extracted.payload.event_id, payload.event_id);
    }

    #[test]
    fn test_partial_fragment_loss_and_recovery() {
        let payload = WatermarkPayload::new(
            "EVT-9f8e7d6c5b4a3928170f1e2d3c4b5a69".to_string(),
            "sha3_doc_hash_1234567890abcdef".to_string(),
            None,
        );

        let payload_bytes = payload.to_bytes().unwrap();
        let framed = create_framed_payload(&payload_bytes, 8, 4).unwrap();
        let rs = ReedSolomon::new(8, 4).unwrap();
        let shard_size = (framed.len() + 8 - 1) / 8;
        let mut padded = framed;
        padded.resize(8 * shard_size, 0);

        let mut shards: Vec<Vec<u8>> = padded.chunks(shard_size).map(|c| c.to_vec()).collect();
        for _ in 0..4 {
            shards.push(vec![0u8; shard_size]);
        }
        rs.encode(&mut shards).unwrap();

        // Tag shards
        let mut tagged_stream = Vec::new();
        for (i, shard) in shards.iter().enumerate() {
            // Drop shard 2 and shard 6 (2 erasures out of 4 parity limit)
            if i != 2 && i != 6 {
                let tagged = create_tagged_shard(i, 12, shard).unwrap();
                tagged_stream.extend_from_slice(&tagged);
            }
        }

        let encoded_zw = encode_zero_width(&tagged_stream);
        let recovered_bytes = extract_watermark_with_ecc(&encoded_zw, 8, 4).unwrap();
        let recovered_payload = WatermarkPayload::from_bytes(&recovered_bytes).unwrap();
        assert_eq!(recovered_payload.event_id, payload.event_id);
    }

    #[test]
    fn test_unsupported_formats_rejected() {
        let manager = MultiLayerWatermarkManager::new();
        let payload = WatermarkPayload::new("EVT-TEST".to_string(), "HASH".to_string(), None);
        let res = manager.embed_multi_layer("sample", &payload, DocumentFormat::Pdf, 8, 4);
        assert!(matches!(
            res,
            Err(WatermarkError::UnsupportedWatermarkFormat(
                DocumentFormat::Pdf
            ))
        ));
    }
}

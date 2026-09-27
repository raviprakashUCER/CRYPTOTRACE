use forensics_service::DecryptionAttestation;
use ledger_core::{
    HashChain, LedgerBlock, LedgerError, LedgerMerkleTree, MerkleInclusionProof, Sha3Algorithm,
};
use rs_merkle::Hasher;
use storage_sqlite::{MerkleBatchRecord, SqliteDatabase, StorageError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum QuorumError {
    #[error("Quorum not reached")]
    QuorumFailed,
    #[error("Ledger operation failed")]
    LedgerFailed(#[from] LedgerError),
    #[error("Storage failure: {0}")]
    StorageFailed(#[from] StorageError),
    #[error("Serialization failed")]
    SerializationError,
    #[error("Ledger integrity failure: {0}")]
    IntegrityFailure(String),
}

pub struct LedgerNode {
    pub node_id: String,
    pub chain: HashChain,
}

impl LedgerNode {
    pub fn new(node_id: &str) -> Self {
        Self {
            node_id: node_id.to_string(),
            chain: HashChain::new(),
        }
    }

    pub fn receive_event(
        &mut self,
        attestation: &DecryptionAttestation,
    ) -> Result<LedgerBlock, QuorumError> {
        let payload =
            bincode::serialize(attestation).map_err(|_| QuorumError::SerializationError)?;
        let block = self.chain.append(&payload)?;
        Ok(block)
    }
}

pub struct LedgerNetwork {
    pub nodes: Vec<LedgerNode>,
    pub required_quorum: usize,
}

impl LedgerNetwork {
    pub fn new(node_count: usize, required_quorum: usize) -> Self {
        let mut nodes = Vec::new();
        for i in 0..node_count {
            nodes.push(LedgerNode::new(&format!("NODE-{}", i)));
        }
        Self {
            nodes,
            required_quorum,
        }
    }

    /// Broadcasts an event to all nodes and checks if quorum is reached
    pub fn broadcast_event(
        &mut self,
        attestation: DecryptionAttestation,
    ) -> Result<String, QuorumError> {
        let mut successful_appends = 0;
        let mut last_hash = String::new();

        for node in &mut self.nodes {
            if let Ok(block) = node.receive_event(&attestation) {
                successful_appends += 1;
                last_hash = block.current_hash;
            }
        }

        if successful_appends >= self.required_quorum {
            Ok(last_hash)
        } else {
            Err(QuorumError::QuorumFailed)
        }
    }
}

// ----------------------------------------------------------------------------
// PERSISTENT SQLITE LEDGER & MERKLE BATCHING (Phase 3)
// ----------------------------------------------------------------------------

pub struct PersistentLedger {
    pub db: SqliteDatabase,
    pub cached_chain: HashChain,
}

impl PersistentLedger {
    /// Loads or initializes persistent ledger from SQLite.
    /// Immediately validates the sequential hash chain to detect any offline tampering.
    pub fn new(db: SqliteDatabase) -> Result<Self, QuorumError> {
        let chain = db
            .load_ledger_chain()
            .map_err(|e| QuorumError::IntegrityFailure(e.to_string()))?;

        Ok(Self {
            db,
            cached_chain: chain,
        })
    }

    /// Records a verified decryption attestation to the persistent ledger.
    pub fn record_attestation(
        &mut self,
        attestation: &DecryptionAttestation,
    ) -> Result<LedgerBlock, QuorumError> {
        let payload =
            bincode::serialize(attestation).map_err(|_| QuorumError::SerializationError)?;

        let block = self.db.append_ledger_block(
            &attestation.event_id,
            &attestation.document_hash,
            &attestation.recipient_id,
            &payload,
        )?;

        self.cached_chain.blocks.push(block.clone());

        let _ = self.db.insert_audit_log(
            "LEDGER_APPEND",
            &attestation.recipient_id,
            &attestation.event_id,
            &format!("Block committed with hash {}", block.current_hash),
            "SUCCESS",
        );

        Ok(block)
    }

    /// Verifies the full tamper-evident sequential hash chain.
    pub fn verify_integrity(&self) -> Result<(), LedgerError> {
        self.cached_chain.verify_detailed()
    }

    /// Constructs a Merkle Tree from all recorded blocks and commits a Merkle Batch.
    pub fn commit_merkle_batch(
        &self,
    ) -> Result<(LedgerMerkleTree, MerkleBatchRecord), QuorumError> {
        let blocks = &self.cached_chain.blocks;
        if blocks.is_empty() {
            return Err(QuorumError::IntegrityFailure(
                "Cannot commit Merkle batch on empty ledger".to_string(),
            ));
        }

        let leaves: Vec<[u8; 32]> = blocks
            .iter()
            .map(|b| Sha3Algorithm::hash(&b.event_payload))
            .collect();

        let tree = LedgerMerkleTree::new(&leaves);
        let root_hex = tree.root_hex().ok_or_else(|| {
            QuorumError::IntegrityFailure("Failed to calculate Merkle root".to_string())
        })?;

        let batch_id = format!("BATCH-{}", uuid::Uuid::new_v4());
        let start_seq = blocks.first().and_then(|b| b.sequence_num).unwrap_or(0);
        let end_seq = blocks.last().and_then(|b| b.sequence_num).unwrap_or(0);

        self.db
            .save_merkle_batch(&batch_id, &root_hex, start_seq, end_seq)?;

        let record = MerkleBatchRecord {
            batch_id,
            merkle_root: root_hex,
            start_seq,
            end_seq,
            created_at: chrono::Utc::now().to_rfc3339(),
        };

        Ok((tree, record))
    }

    /// Generates a Merkle inclusion proof for a given event ID in the committed batch.
    pub fn generate_inclusion_proof_for_event(
        &self,
        event_id: &str,
    ) -> Result<Option<MerkleInclusionProof>, QuorumError> {
        let blocks = &self.cached_chain.blocks;
        let position = blocks.iter().position(|b| {
            if let Ok(att) = bincode::deserialize::<DecryptionAttestation>(&b.event_payload) {
                att.event_id == event_id
            } else {
                false
            }
        });

        let leaf_index = match position {
            Some(idx) => idx,
            None => return Ok(None),
        };

        let leaves: Vec<[u8; 32]> = blocks
            .iter()
            .map(|b| Sha3Algorithm::hash(&b.event_payload))
            .collect();

        let tree = LedgerMerkleTree::new(&leaves);
        let proof = tree
            .generate_inclusion_proof(leaf_index)
            .map_err(QuorumError::LedgerFailed)?;

        Ok(Some(proof))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use identity_core::generate_ml_dsa_keypair;
    use pqcrypto_traits::sign::SecretKey as _;

    #[test]
    fn test_persistent_ledger_lifecycle() {
        let db = SqliteDatabase::open_in_memory().unwrap();
        let mut ledger = PersistentLedger::new(db.clone()).unwrap();

        let (_, dsa_sk) = generate_ml_dsa_keypair();
        let attestation = DecryptionAttestation {
            event_id: "EVT-PERSIST-1".to_string(),
            document_hash: "HASH-123".to_string(),
            recipient_id: "OFFICER-1".to_string(),
            session_id: "SESSION-1".to_string(),
            timestamp: chrono::Utc::now(),
            signature: dsa_sk.as_bytes().to_vec(),
        };

        let block = ledger.record_attestation(&attestation).unwrap();
        assert_eq!(block.sequence_num, Some(0));

        // Verify chain integrity
        assert!(ledger.verify_integrity().is_ok());

        // Commit Merkle batch and generate proof
        let (_tree, batch) = ledger.commit_merkle_batch().unwrap();
        assert!(!batch.merkle_root.is_empty());

        let proof = ledger
            .generate_inclusion_proof_for_event("EVT-PERSIST-1")
            .unwrap()
            .expect("Proof should exist");

        let payload = bincode::serialize(&attestation).unwrap();
        let leaf = Sha3Algorithm::hash(&payload);

        assert!(LedgerMerkleTree::verify_inclusion(&proof, &leaf));
    }
}

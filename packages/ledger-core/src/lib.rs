use rs_merkle::{Hasher, MerkleProof, MerkleTree};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use thiserror::Error;

#[derive(Clone)]
pub struct Sha3Algorithm;

impl Hasher for Sha3Algorithm {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let res = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&res);
        out
    }
}

#[derive(Error, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LedgerError {
    #[error("Hash chain verification failed: block {block_index} broken")]
    InvalidChain { block_index: usize },
    #[error("Merkle proof generation failed: {0}")]
    ProofGenerationError(String),
    #[error("Merkle proof verification failed: invalid leaf or path")]
    InvalidMerkleProof,
    #[error("Serialization failed")]
    SerializationError,
    #[error("Database persistence error: {0}")]
    PersistenceError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerBlock {
    pub sequence_num: Option<i64>,
    pub previous_hash: String,
    pub event_payload: Vec<u8>,
    pub current_hash: String,
    pub timestamp: String,
}

#[derive(Clone)]
pub struct HashChain {
    pub blocks: Vec<LedgerBlock>,
}

impl Default for HashChain {
    fn default() -> Self {
        Self::new()
    }
}

impl HashChain {
    pub fn new() -> Self {
        Self { blocks: Vec::new() }
    }

    pub fn get_blocks(&self) -> &[LedgerBlock] {
        &self.blocks
    }

    pub fn append(&mut self, payload: &[u8]) -> Result<LedgerBlock, LedgerError> {
        let previous_hash = match self.blocks.last() {
            Some(block) => block.current_hash.clone(),
            None => {
                String::from("0000000000000000000000000000000000000000000000000000000000000000")
            } // Genesis block
        };

        let mut data = Vec::new();
        data.extend_from_slice(previous_hash.as_bytes());
        data.extend_from_slice(payload);

        let current_hash = hex::encode(Sha3Algorithm::hash(&data));

        let block = LedgerBlock {
            sequence_num: Some(self.blocks.len() as i64),
            previous_hash,
            event_payload: payload.to_vec(),
            current_hash,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        self.blocks.push(block.clone());
        Ok(block)
    }

    pub fn verify(&self) -> bool {
        self.verify_detailed().is_ok()
    }

    pub fn verify_detailed(&self) -> Result<(), LedgerError> {
        for (i, block) in self.blocks.iter().enumerate() {
            if i > 0 {
                if block.previous_hash != self.blocks[i - 1].current_hash {
                    return Err(LedgerError::InvalidChain { block_index: i });
                }
            } else if block.previous_hash
                != "0000000000000000000000000000000000000000000000000000000000000000"
            {
                return Err(LedgerError::InvalidChain { block_index: 0 });
            }

            let mut data = Vec::new();
            data.extend_from_slice(block.previous_hash.as_bytes());
            data.extend_from_slice(&block.event_payload);

            let calculated_hash = hex::encode(Sha3Algorithm::hash(&data));
            if calculated_hash != block.current_hash {
                return Err(LedgerError::InvalidChain { block_index: i });
            }
        }
        Ok(())
    }
}

// ----------------------------------------------------------------------------
// MERKLE TREE & INCLUSION PROOFS (Phase 3)
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleInclusionProof {
    pub leaf_index: usize,
    pub total_leaves: usize,
    pub proof_hashes: Vec<String>, // Hex encoded sibling proof hashes
    pub root_hash: String,
}

pub struct LedgerMerkleTree {
    tree: MerkleTree<Sha3Algorithm>,
    leaves: Vec<[u8; 32]>,
}

impl LedgerMerkleTree {
    pub fn new(leaves: &[[u8; 32]]) -> Self {
        Self {
            tree: MerkleTree::<Sha3Algorithm>::from_leaves(leaves),
            leaves: leaves.to_vec(),
        }
    }

    pub fn from_payloads(payloads: &[&[u8]]) -> Self {
        let leaves: Vec<[u8; 32]> = payloads.iter().map(|p| Sha3Algorithm::hash(p)).collect();
        Self::new(&leaves)
    }

    pub fn root(&self) -> Option<[u8; 32]> {
        self.tree.root()
    }

    pub fn root_hex(&self) -> Option<String> {
        self.root().map(hex::encode)
    }

    pub fn generate_inclusion_proof(
        &self,
        leaf_index: usize,
    ) -> Result<MerkleInclusionProof, LedgerError> {
        if leaf_index >= self.leaves.len() {
            return Err(LedgerError::ProofGenerationError(format!(
                "Leaf index {} out of bounds (total {})",
                leaf_index,
                self.leaves.len()
            )));
        }

        let root_hash = self.root_hex().ok_or_else(|| {
            LedgerError::ProofGenerationError("Cannot generate proof on empty tree".to_string())
        })?;

        let proof = self.tree.proof(&[leaf_index]);
        let proof_hashes: Vec<String> = proof.proof_hashes().iter().map(hex::encode).collect();

        Ok(MerkleInclusionProof {
            leaf_index,
            total_leaves: self.leaves.len(),
            proof_hashes,
            root_hash,
        })
    }

    pub fn verify_inclusion(proof: &MerkleInclusionProof, leaf_hash: &[u8; 32]) -> bool {
        let mut proof_bytes = Vec::new();
        for h_str in &proof.proof_hashes {
            if let Ok(bytes) = hex::decode(h_str) {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    proof_bytes.push(arr);
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }

        let rs_proof = MerkleProof::<Sha3Algorithm>::new(proof_bytes);
        let root_bytes = match hex::decode(&proof.root_hash) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            _ => return false,
        };

        rs_proof.verify(
            root_bytes,
            &[proof.leaf_index],
            &[*leaf_hash],
            proof.total_leaves,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_inclusion_proof_valid_and_tampered() {
        let leaves = vec![
            Sha3Algorithm::hash(b"event-1"),
            Sha3Algorithm::hash(b"event-2"),
            Sha3Algorithm::hash(b"event-3"),
            Sha3Algorithm::hash(b"event-4"),
        ];

        let tree = LedgerMerkleTree::new(&leaves);
        let root = tree.root().unwrap();
        assert!(!root.is_empty());

        // Test inclusion proof for leaf 2
        let proof = tree.generate_inclusion_proof(2).unwrap();
        assert_eq!(proof.leaf_index, 2);
        assert_eq!(proof.total_leaves, 4);

        // Valid verification
        assert!(LedgerMerkleTree::verify_inclusion(&proof, &leaves[2]));

        // Wrong leaf fails
        assert!(!LedgerMerkleTree::verify_inclusion(&proof, &leaves[0]));

        // Wrong root fails
        let mut bad_proof = proof.clone();
        bad_proof.root_hash = hex::encode([0u8; 32]);
        assert!(!LedgerMerkleTree::verify_inclusion(&bad_proof, &leaves[2]));

        // Modified proof sibling fails
        let mut tampered_proof = proof.clone();
        if !tampered_proof.proof_hashes.is_empty() {
            tampered_proof.proof_hashes[0] = hex::encode([0xff; 32]);
            assert!(!LedgerMerkleTree::verify_inclusion(
                &tampered_proof,
                &leaves[2]
            ));
        }
    }
}

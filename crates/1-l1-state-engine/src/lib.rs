pub mod consensus;
pub mod executor;
pub mod shuffler;
pub mod state_db;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid transaction, configuration, or input")]
    InvalidInput,
    #[error("unauthorized actor or unregistered mobile node")]
    Unauthorized,
    #[error("P-256 signature or hardware attestation verification failed")]
    BadSignature,
    #[error("unexpected epoch sequence or stale replay")]
    BadEpoch,
    #[error("KZG proof, VRF sample, or homomorphic repair audit failed")]
    BadProof,
    #[error("insufficient stake or storage bounty balance")]
    InsufficientBalance,
    #[error("heartbeat fault proof rejected: node already marked online or already penalized")]
    InvalidFaultProof,
    #[error("BFT consensus quorum (>2/3) not reached")]
    ConsensusFailed,
}

pub type Result<T> = std::result::Result<T, Error>;

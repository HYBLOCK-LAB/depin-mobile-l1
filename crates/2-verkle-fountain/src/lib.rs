pub mod fountain;
pub mod pollution_guard;
pub mod verkle_kzg;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid parameters or input data")]
    InvalidInput,
    #[error("insufficient linearly independent shards to decode (rank below k)")]
    InsufficientRank,
    #[error("cryptographic serialization or KZG verification failed")]
    CryptoFailure,
    #[error("pollution detected: candidate shard violates homomorphic linear relation")]
    PollutionDetected,
}

pub type Result<T> = std::result::Result<T, Error>;

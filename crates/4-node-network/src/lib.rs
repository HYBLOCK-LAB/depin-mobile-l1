pub mod client;
pub mod l1_daemon;
pub mod persistence;
pub mod storage_daemon;
pub mod wire;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("l1 engine error: {0}")]
    L1(#[from] l1_state_engine::Error),
    #[error("fountain/kzg error: {0}")]
    Verkle(#[from] verkle_fountain::Error),
    #[error("swarm protocol error: {0}")]
    Swarm(#[from] swarm_protocol::Error),
    #[error("rpc/network error: {0}")]
    Network(String),
}

pub type Result<T> = std::result::Result<T, Error>;

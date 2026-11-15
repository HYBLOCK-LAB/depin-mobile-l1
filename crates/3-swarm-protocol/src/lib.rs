pub mod churn_sim;
pub mod lazy_repair_fsm;
pub mod swarm_coordinator;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid configuration, slot index, or state")]
    Invalid,
    #[error("data temporarily unavailable (linearly independent online rank below k)")]
    Unavailable,
    #[error("local F_p repair or homomorphic verification failed")]
    RepairFailed,
    #[error("no online aggregator or checkpoint assembly failure")]
    CoordinatorFailed,
}

pub type Result<T> = std::result::Result<T, Error>;

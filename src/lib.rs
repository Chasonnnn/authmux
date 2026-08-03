//! Authentication-context policy and execution orchestration.

mod aws_adapter;
mod config;
mod context_engine;
mod domain;
mod process_runner;

pub use aws_adapter::AwsAdapter;
pub use config::{ConfigFailure, ContextDefinition, ProjectBinding, UserConfig};
pub use context_engine::{ContextEngine, ProcessRunner, ProviderAdapter};
pub use domain::{
    AuthenticationContext, CommandSpec, DomainFailure, EvidenceLevel, ExecutionFailure,
    ExecutionOutcome, ExecutionSelection, IdentityMatch, ObservationReason, ObservedIdentity,
    ProviderFailure, ReauthenticationNeed, SessionUsability, StatusObservation,
};
pub use process_runner::SecureProcessRunner;
pub use process_runner::{ProbeOutput, ProbePolicy, ProbeRunner};

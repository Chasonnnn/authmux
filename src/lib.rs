//! Authentication-context policy and execution orchestration.

mod aws_adapter;
mod config;
mod context_engine;
mod doctor;
mod domain;
mod presentation;
mod process_runner;
mod ssh_readiness;

pub use aws_adapter::{AwsAdapter, AwsLocalMetadataAdapter};
pub use config::{
    ConfigFailure, ContextDefinition, ProjectBinding, SshProviderDefinition, UserConfig,
};
pub use context_engine::{
    ContextEngine, ExecutionContextResolver, ProcessRunner, ProviderAdapter, StatusAdapter,
    StatusEngine,
};
pub use doctor::{AwsDoctor, DoctorCheck, DoctorOutcome, DoctorResult};
pub use domain::{
    AuthenticationContext, CommandSpec, DomainFailure, EvidenceLevel, ExecutionFailure,
    ExecutionOutcome, ExecutionSelection, IdentityMatch, ObservationReason, ObservedIdentity,
    ProviderFailure, ReauthenticationNeed, SessionUsability, StatusObservation,
};
pub use presentation::{ContextListReport, DoctorReport, PresentationFailure, StatusReport};
pub use process_runner::SecureProcessRunner;
pub use process_runner::{ProbeOutput, ProbePolicy, ProbeRunner};
pub use ssh_readiness::{SshClientReadiness, SshClientReadinessCheck};

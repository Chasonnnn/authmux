//! Authentication-context policy and execution orchestration.

mod aws_adapter;
mod config;
mod context_engine;
mod doctor;
mod domain;
#[cfg(unix)]
mod gcp_exec;
#[cfg(unix)]
mod gcp_login;
#[cfg(unix)]
mod gcp_status;
mod presentation;
mod process_runner;
mod ssh_readiness;
#[cfg(unix)]
mod ssh_transport_status;

pub use aws_adapter::{AwsAdapter, AwsLocalMetadataAdapter};
pub use config::{
    ConfigFailure, ContextDefinition, GcloudProviderDefinition, GcpAdcProviderDefinition,
    GcpProviderDefinition, ProjectBinding, SshProviderDefinition, UserConfig,
};
pub use context_engine::{
    ContextEngine, ExecutionContextResolver, ProcessRunner, ProviderAdapter, StatusAdapter,
    StatusEngine,
};
#[cfg(unix)]
pub use doctor::GcpDoctor;
pub use doctor::{AwsDoctor, DoctorCheck, DoctorOutcome, DoctorResult, SshDoctor};
pub use domain::{
    AuthenticationContext, CommandSpec, DomainFailure, EvidenceLevel, ExecutionFailure,
    ExecutionOutcome, ExecutionSelection, IdentityMatch, ObservationReason, ObservedIdentity,
    ProviderFailure, ReauthenticationNeed, SessionUsability, StatusObservation,
};
#[cfg(unix)]
pub use gcp_exec::{GcpExecutionFailure, GcpExecutionGuard};
#[cfg(unix)]
pub use gcp_login::{GcpLoginFailure, GcpLoginPlan};
#[cfg(unix)]
pub use gcp_status::{GcpCredentialPlane, GcpLocalStatus, GcpPlaneObservation, GcpProjectMatch};
pub use presentation::{ContextListReport, DoctorReport, PresentationFailure, StatusReport};
pub use process_runner::SecureProcessRunner;
pub use process_runner::{ProbeOutput, ProbePolicy, ProbeRunner};
pub use ssh_readiness::{SshClientReadiness, SshClientReadinessCheck};
#[cfg(unix)]
pub use ssh_transport_status::{SshTransportObservation, SshTransportReuse, SshTransportStatus};

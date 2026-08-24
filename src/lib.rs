//! Authentication-context policy and execution orchestration.

mod aws_adapter;
#[cfg(unix)]
mod aws_login;
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
mod github_status;
mod presentation;
mod process_runner;
mod ssh_readiness;
#[cfg(unix)]
mod ssh_transport_status;

pub use aws_adapter::{AwsAdapter, AwsLocalMetadataAdapter};
#[cfg(unix)]
pub use aws_login::{AwsLoginFailure, AwsLoginMode, AwsLoginPlan, AwsLoginPlanner};
pub use config::{
    ConfigFailure, ContextDefinition, GcloudProviderDefinition, GcpAdcProviderDefinition,
    GcpProviderDefinition, GithubProviderDefinition, ProjectBinding, SshProviderDefinition,
    UserConfig,
};
pub use context_engine::{
    ContextEngine, ExecutionContextResolver, ProcessRunner, ProviderAdapter, StatusAdapter,
    StatusEngine,
};
#[cfg(unix)]
pub use doctor::GcpDoctor;
pub use doctor::{AwsDoctor, DoctorCheck, DoctorOutcome, DoctorResult, GithubDoctor, SshDoctor};
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
pub use github_status::{GithubExecutionGuard, GithubGuardFailure, GithubLoginPlan, GithubStatus};
pub use presentation::{
    AllStatusReport, ContextListReport, DoctorReport, PresentationFailure, ReauthenticationEvent,
    StatusReport,
};
pub use process_runner::SecureProcessRunner;
pub use process_runner::{ProbeOutput, ProbePolicy, ProbeRunner};
pub use ssh_readiness::{SshClientReadiness, SshClientReadinessCheck};
#[cfg(unix)]
pub use ssh_transport_status::{SshTransportObservation, SshTransportReuse, SshTransportStatus};

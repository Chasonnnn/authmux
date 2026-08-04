use std::error::Error;
use std::fmt;
use std::path::Path;

use crate::{
    CommandSpec, ContextDefinition, ExecutionSelection, GcpCredentialPlane, GcpPlaneObservation,
    GcpProjectMatch, GcpProviderDefinition, IdentityMatch, ObservationReason,
};

/// Applies the local-selection guard for an explicit GCP child execution.
pub struct GcpExecutionGuard;

impl GcpExecutionGuard {
    /// Produces selectors only when the credential plane required by the child
    /// has the protected local evidence accepted by ADR 0007.
    ///
    /// # Errors
    ///
    /// Fails closed on missing planes, mismatched selection, or unavailable
    /// protected metadata. It never treats local evidence as live usability.
    pub fn authorize(
        profile: &GcpProviderDefinition,
        observations: &[GcpPlaneObservation],
        command: &CommandSpec,
    ) -> Result<ExecutionSelection, GcpExecutionFailure> {
        if is_gcloud(command) {
            authorize_gcloud(profile, observations)?;
        } else {
            authorize_adc(profile, observations)?;
        }
        Ok(profile.execution_selection())
    }

    /// Verifies that the material GCP execution context is unchanged at the
    /// final pre-spawn resolution point.
    ///
    /// # Errors
    ///
    /// Fails when the context name, GCP profile, or provider composition
    /// changed after observation.
    pub fn ensure_unchanged(
        initial: &ContextDefinition,
        current: &ContextDefinition,
    ) -> Result<(), GcpExecutionFailure> {
        if initial.name() != current.name()
            || initial.gcp() != current.gcp()
            || initial.aws().is_some() != current.aws().is_some()
            || initial.ssh().is_some() != current.ssh().is_some()
        {
            return Err(GcpExecutionFailure::ContextChanged);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcpExecutionFailure {
    GcloudPlaneRequired,
    AdcPlaneRequired,
    IdentityMismatch,
    SourceIdentityMismatch,
    ProjectMismatch,
    GcloudSelectionUnavailable,
    AdcSelectionUnavailable,
    UnsupportedProviderComposition,
    ContextChanged,
}

impl GcpExecutionFailure {
    #[must_use]
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::GcloudPlaneRequired
            | Self::AdcPlaneRequired
            | Self::UnsupportedProviderComposition => 2,
            Self::IdentityMismatch | Self::SourceIdentityMismatch | Self::ProjectMismatch => 3,
            Self::GcloudSelectionUnavailable | Self::AdcSelectionUnavailable => 4,
            Self::ContextChanged => 6,
        }
    }
}

impl fmt::Display for GcpExecutionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::GcloudPlaneRequired => {
                "refusing child execution: gcloud requires a declared GCP gcloud CLI plane"
            }
            Self::AdcPlaneRequired => {
                "refusing child execution: non-gcloud GCP children require an explicit ADC credential-file plane"
            }
            Self::IdentityMismatch => {
                "refusing child execution: expected GCP identity does not match the protected local gcloud selection"
            }
            Self::SourceIdentityMismatch => {
                "refusing child execution: expected GCP source identity does not match the protected local gcloud selection"
            }
            Self::ProjectMismatch => {
                "refusing child execution: expected GCP project does not match the protected local gcloud selection"
            }
            Self::GcloudSelectionUnavailable => {
                "refusing child execution: protected local gcloud selection evidence is unavailable"
            }
            Self::AdcSelectionUnavailable => {
                "refusing child execution: protected ADC credential-file selection is unavailable"
            }
            Self::UnsupportedProviderComposition => {
                "refusing child execution: GCP execution cannot yet be composed with another provider"
            }
            Self::ContextChanged => {
                "refusing child execution: authentication context changed after provider validation; retry the command"
            }
        })
    }
}

impl Error for GcpExecutionFailure {}

fn is_gcloud(command: &CommandSpec) -> bool {
    Path::new(command.program())
        .file_name()
        .is_some_and(|name| name == "gcloud")
}

fn authorize_gcloud(
    profile: &GcpProviderDefinition,
    observations: &[GcpPlaneObservation],
) -> Result<(), GcpExecutionFailure> {
    let gcloud = profile
        .gcloud()
        .ok_or(GcpExecutionFailure::GcloudPlaneRequired)?;
    let observation = observations
        .iter()
        .find(|observation| observation.plane() == GcpCredentialPlane::GcloudCli)
        .ok_or(GcpExecutionFailure::GcloudSelectionUnavailable)?;
    if observation.status().identity_match() == IdentityMatch::Mismatch {
        return Err(GcpExecutionFailure::IdentityMismatch);
    }
    if observation.status().identity_match() != IdentityMatch::Match
        || observation.status().reason() != Some(ObservationReason::InsufficientEvidence)
    {
        return Err(GcpExecutionFailure::GcloudSelectionUnavailable);
    }
    if gcloud.expected_source_account().is_some() {
        match observation.source_identity_match() {
            Some(IdentityMatch::Match) => {}
            Some(IdentityMatch::Mismatch) => {
                return Err(GcpExecutionFailure::SourceIdentityMismatch);
            }
            Some(IdentityMatch::Unverified) | None => {
                return Err(GcpExecutionFailure::GcloudSelectionUnavailable);
            }
        }
    }
    if gcloud.expected_project().is_some() {
        match observation.project_match() {
            GcpProjectMatch::Match => {}
            GcpProjectMatch::Mismatch => return Err(GcpExecutionFailure::ProjectMismatch),
            GcpProjectMatch::Unverified | GcpProjectMatch::NotApplicable => {
                return Err(GcpExecutionFailure::GcloudSelectionUnavailable);
            }
        }
    }
    Ok(())
}

fn authorize_adc(
    profile: &GcpProviderDefinition,
    observations: &[GcpPlaneObservation],
) -> Result<(), GcpExecutionFailure> {
    profile.adc().ok_or(GcpExecutionFailure::AdcPlaneRequired)?;
    let observation = observations
        .iter()
        .find(|observation| observation.plane() == GcpCredentialPlane::Adc)
        .ok_or(GcpExecutionFailure::AdcSelectionUnavailable)?;
    if observation.status().reason() != Some(ObservationReason::InsufficientEvidence) {
        return Err(GcpExecutionFailure::AdcSelectionUnavailable);
    }
    Ok(())
}

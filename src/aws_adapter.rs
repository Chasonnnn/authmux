use std::str;
use std::time::Duration;

use crate::{
    AuthenticationContext, CommandSpec, EvidenceLevel, ExecutionSelection, ObservationReason,
    ObservedIdentity, ProbePolicy, ProbeRunner, ProviderAdapter, ProviderFailure,
    ReauthenticationNeed, StatusAdapter, StatusObservation,
};

pub struct AwsAdapter<R> {
    runner: R,
}

pub struct AwsLocalMetadataAdapter<R> {
    runner: R,
}

impl<R> AwsLocalMetadataAdapter<R> {
    #[must_use]
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl<R> AwsLocalMetadataAdapter<R>
where
    R: ProbeRunner,
{
    fn probe_setting(
        &self,
        context: &AuthenticationContext,
        setting: &str,
    ) -> Result<crate::ProbeOutput, ProviderFailure> {
        let command = CommandSpec::new(
            "aws",
            [
                "configure",
                "get",
                setting,
                "--profile",
                context.provider_profile(),
            ],
        )?;
        self.runner.probe(
            &command,
            &ExecutionSelection::none(),
            ProbePolicy::bounded(Duration::from_secs(2), 4_096),
        )
    }
}

impl<R> AwsAdapter<R> {
    #[must_use]
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl<R> ProviderAdapter for AwsAdapter<R>
where
    R: ProbeRunner,
{
    fn observe(
        &self,
        context: &AuthenticationContext,
    ) -> Result<StatusObservation, ProviderFailure> {
        let command = CommandSpec::new(
            "aws",
            [
                "sts",
                "get-caller-identity",
                "--query",
                "Account",
                "--output",
                "text",
                "--no-cli-pager",
                "--no-cli-auto-prompt",
            ],
        )?;
        let selection = ExecutionSelection::aws_profile(context.provider_profile());
        let output = self.runner.probe(
            &command,
            &selection,
            ProbePolicy::bounded(Duration::from_secs(5), 4_096),
        )?;

        if output.was_truncated() {
            return Err(ProviderFailure::sanitized(
                "AWS identity observation exceeded the safe output limit",
            ));
        }
        if output.exit_code() != 0 {
            return Err(ProviderFailure::sanitized(
                "AWS identity observation failed; run `authmux login` for this context",
            ));
        }

        let account = str::from_utf8(output.stdout())
            .map_err(|_| ProviderFailure::sanitized("AWS returned a malformed account identity"))?
            .trim();
        let observed_identity = ObservedIdentity::aws_account(account)?;

        Ok(StatusObservation::usable_provider_validation(
            observed_identity,
        ))
    }

    fn execution_selection(
        &self,
        context: &AuthenticationContext,
    ) -> Result<ExecutionSelection, ProviderFailure> {
        Ok(ExecutionSelection::aws_profile(context.provider_profile()))
    }
}

impl<R> StatusAdapter for AwsLocalMetadataAdapter<R>
where
    R: ProbeRunner,
{
    fn observe_status(
        &self,
        context: &AuthenticationContext,
    ) -> Result<StatusObservation, ProviderFailure> {
        let output = self.probe_setting(context, "sso_account_id")?;

        if output.was_truncated() {
            return Ok(indeterminate_local(ObservationReason::ProviderError));
        }
        if output.exit_code() == 0 {
            let Ok(account) = str::from_utf8(output.stdout()) else {
                return Ok(indeterminate_local(ObservationReason::ProviderError));
            };
            let Ok(observed_identity) = ObservedIdentity::aws_account(account.trim()) else {
                return Ok(indeterminate_local(ObservationReason::ProviderError));
            };

            return Ok(indeterminate_with_identity(observed_identity));
        }

        let login_output = self.probe_setting(context, "login_session")?;
        if login_output.was_truncated() {
            return Ok(indeterminate_local(ObservationReason::ProviderError));
        }
        if login_output.exit_code() != 0 {
            return Ok(indeterminate_local(ObservationReason::InsufficientEvidence));
        }

        let Ok(login_session) = str::from_utf8(login_output.stdout()) else {
            return Ok(indeterminate_local(ObservationReason::ProviderError));
        };
        let Some(account) = login_session_account(login_session.trim()) else {
            return Ok(indeterminate_local(ObservationReason::ProviderError));
        };
        let Ok(observed_identity) = ObservedIdentity::aws_account(account) else {
            return Ok(indeterminate_local(ObservationReason::ProviderError));
        };

        Ok(indeterminate_with_identity(observed_identity))
    }
}

pub(crate) fn login_session_account(login_session: &str) -> Option<&str> {
    let parts = login_session.split(':').collect::<Vec<_>>();
    let ["arn", partition, service, "", account, resource] = parts.as_slice() else {
        return None;
    };
    if !matches!(*partition, "aws" | "aws-us-gov" | "aws-cn")
        || !matches!(*service, "iam" | "sts")
        || account.len() != 12
        || !account.bytes().all(|byte| byte.is_ascii_digit())
        || !resource.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return None;
    }
    let supported_resource = match *service {
        "iam" => {
            *resource == "root" || resource.starts_with("user/") || resource.starts_with("role/")
        }
        "sts" => resource.starts_with("assumed-role/") || resource.starts_with("federated-user/"),
        _ => false,
    };
    supported_resource.then_some(account)
}

fn indeterminate_with_identity(observed_identity: ObservedIdentity) -> StatusObservation {
    StatusObservation::indeterminate(
        observed_identity,
        ObservationReason::InsufficientEvidence,
        ReauthenticationNeed::Unknown,
        EvidenceLevel::LocalMetadata,
    )
}

fn indeterminate_local(reason: ObservationReason) -> StatusObservation {
    StatusObservation::indeterminate_without_identity(
        reason,
        ReauthenticationNeed::Unknown,
        EvidenceLevel::LocalMetadata,
    )
}

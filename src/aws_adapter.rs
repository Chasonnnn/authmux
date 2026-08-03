use std::str;
use std::time::Duration;

use crate::{
    AuthenticationContext, CommandSpec, ExecutionSelection, ObservedIdentity, ProbePolicy,
    ProbeRunner, ProviderAdapter, ProviderFailure, StatusObservation,
};

pub struct AwsAdapter<R> {
    runner: R,
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

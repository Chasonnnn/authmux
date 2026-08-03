use std::str;
use std::time::Duration;

use crate::{
    AuthenticationContext, AwsLocalMetadataAdapter, CommandSpec, ExecutionSelection, IdentityMatch,
    ObservationReason, ProbePolicy, ProbeRunner, StatusEngine,
};

pub struct AwsDoctor<VR, SR> {
    version_runner: VR,
    status_runner: SR,
}

impl<VR, SR> AwsDoctor<VR, SR>
where
    VR: ProbeRunner,
    SR: ProbeRunner,
{
    #[must_use]
    pub fn new(version_runner: VR, status_runner: SR) -> Self {
        Self {
            version_runner,
            status_runner,
        }
    }

    #[must_use]
    pub fn diagnose(&self, context: &AuthenticationContext) -> DoctorResult {
        let checks = vec![
            DoctorCheck::pass("configuration", "context resolved"),
            observe_aws_version(&self.version_runner),
            observe_profile_identity(&self.status_runner, context),
        ];
        DoctorResult {
            context: context.name().to_owned(),
            provider_contacted: false,
            checks,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DoctorOutcome {
    Pass,
    Warning,
    Fail,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctorCheck {
    id: &'static str,
    outcome: DoctorOutcome,
    summary: String,
}

impl DoctorCheck {
    fn pass(id: &'static str, summary: impl Into<String>) -> Self {
        Self {
            id,
            outcome: DoctorOutcome::Pass,
            summary: summary.into(),
        }
    }

    fn warning(id: &'static str, summary: impl Into<String>) -> Self {
        Self {
            id,
            outcome: DoctorOutcome::Warning,
            summary: summary.into(),
        }
    }

    fn fail(id: &'static str, summary: impl Into<String>) -> Self {
        Self {
            id,
            outcome: DoctorOutcome::Fail,
            summary: summary.into(),
        }
    }

    #[must_use]
    pub fn id(&self) -> &'static str {
        self.id
    }

    #[must_use]
    pub fn outcome(&self) -> DoctorOutcome {
        self.outcome
    }

    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctorResult {
    context: String,
    provider_contacted: bool,
    checks: Vec<DoctorCheck>,
}

impl DoctorResult {
    #[must_use]
    pub fn context(&self) -> &str {
        &self.context
    }

    #[must_use]
    pub fn provider_contacted(&self) -> bool {
        self.provider_contacted
    }

    #[must_use]
    pub fn checks(&self) -> &[DoctorCheck] {
        &self.checks
    }

    #[must_use]
    pub fn outcome(&self) -> DoctorOutcome {
        if self
            .checks
            .iter()
            .any(|check| check.outcome == DoctorOutcome::Fail)
        {
            DoctorOutcome::Fail
        } else if self
            .checks
            .iter()
            .any(|check| check.outcome == DoctorOutcome::Warning)
        {
            DoctorOutcome::Warning
        } else {
            DoctorOutcome::Pass
        }
    }
}

fn observe_aws_version<R>(runner: &R) -> DoctorCheck
where
    R: ProbeRunner,
{
    let Ok(command) = CommandSpec::new("aws", ["--version"]) else {
        return DoctorCheck::fail("aws_cli", "AWS CLI version command is invalid");
    };
    let Ok(output) = runner.probe(
        &command,
        &ExecutionSelection::none(),
        ProbePolicy::bounded(Duration::from_secs(2), 4_096),
    ) else {
        return DoctorCheck::fail("aws_cli", "AWS CLI could not be executed safely");
    };
    if output.exit_code() != 0 || output.was_truncated() {
        return DoctorCheck::fail("aws_cli", "AWS CLI version could not be determined");
    }

    let bytes = if output.stdout().is_empty() {
        output.stderr()
    } else {
        output.stdout()
    };
    let Some((major, version)) = parse_aws_cli_version(bytes) else {
        return DoctorCheck::fail("aws_cli", "AWS CLI version output was not recognized");
    };
    if major != 2 {
        return DoctorCheck::fail("aws_cli", "AWS CLI v2 is required");
    }

    DoctorCheck::pass("aws_cli", format!("AWS CLI {version} is supported"))
}

fn parse_aws_cli_version(bytes: &[u8]) -> Option<(u32, String)> {
    let text = str::from_utf8(bytes).ok()?.trim();
    let version = text
        .split_ascii_whitespace()
        .next()?
        .strip_prefix("aws-cli/")?;
    if version.len() > 32 {
        return None;
    }
    let components = version.split('.').collect::<Vec<_>>();
    if components.len() != 3
        || components.iter().any(|component| {
            component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return None;
    }
    let major = components[0].parse().ok()?;
    Some((major, version.to_owned()))
}

fn observe_profile_identity<R>(runner: &R, context: &AuthenticationContext) -> DoctorCheck
where
    R: ProbeRunner,
{
    let engine = StatusEngine::new(AwsLocalMetadataAdapter::new(runner));
    let Ok(observation) = engine.observe(context) else {
        return DoctorCheck::fail(
            "aws_profile_identity",
            "AWS profile metadata could not be inspected safely",
        );
    };

    match observation.identity_match() {
        IdentityMatch::Match => DoctorCheck::pass(
            "aws_profile_identity",
            "configured account matches expected identity",
        ),
        IdentityMatch::Mismatch => DoctorCheck::fail(
            "aws_profile_identity",
            "configured account does not match expected identity",
        ),
        IdentityMatch::Unverified
            if observation.reason() == Some(ObservationReason::ProviderError) =>
        {
            DoctorCheck::fail("aws_profile_identity", "AWS profile metadata was malformed")
        }
        IdentityMatch::Unverified => DoctorCheck::warning(
            "aws_profile_identity",
            "AWS profile has no supported local account metadata",
        ),
    }
}

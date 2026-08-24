use std::str;
use std::time::Duration;

#[cfg(unix)]
use std::ffi::{OsStr, OsString};
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
#[cfg(unix)]
use std::path::PathBuf;

use crate::{
    AuthenticationContext, AwsLocalMetadataAdapter, CommandSpec, ExecutionSelection,
    GithubProviderDefinition, IdentityMatch, ObservationReason, ProbePolicy, ProbeRunner,
    SshClientReadinessCheck, SshProviderDefinition, StatusEngine,
};
#[cfg(unix)]
use crate::{
    GcpCredentialPlane, GcpLocalStatus, GcpPlaneObservation, GcpProjectMatch, GcpProviderDefinition,
};

pub struct AwsDoctor<VR, SR> {
    version_runner: VR,
    status_runner: SR,
}

pub struct SshDoctor<R> {
    runner: R,
}

pub struct GithubDoctor<R> {
    runner: R,
}

impl<R> GithubDoctor<R>
where
    R: ProbeRunner,
{
    #[must_use]
    pub fn new(runner: R) -> Self {
        Self { runner }
    }

    #[must_use]
    pub fn diagnose(&self, context_name: &str, profile: &GithubProviderDefinition) -> DoctorResult {
        let configuration = DoctorCheck::pass("configuration", "GitHub Provider Profile resolved");
        let cli = observe_github_version(&self.runner, profile);
        DoctorResult {
            context: context_name.to_owned(),
            provider_contacted: false,
            checks: vec![
                configuration,
                cli,
                DoctorCheck::warning(
                    "session_continuity",
                    "GitHub has no supported automatic Credential renewal contract; an unusable Session requires external login",
                ),
            ],
        }
    }
}

#[cfg(unix)]
pub struct GcpDoctor {
    home: PathBuf,
    search_path: Option<OsString>,
}

#[cfg(unix)]
impl GcpDoctor {
    #[must_use]
    pub fn new(home: impl Into<PathBuf>, search_path: Option<OsString>) -> Self {
        Self {
            home: home.into(),
            search_path,
        }
    }

    #[must_use]
    pub fn diagnose(&self, context_name: &str, profile: &GcpProviderDefinition) -> DoctorResult {
        let mut checks = vec![DoctorCheck::pass(
            "configuration",
            "GCP credential planes resolved",
        )];
        if profile.gcloud().is_some() {
            checks.push(
                if gcloud_executable_available(self.search_path.as_deref()) {
                    DoctorCheck::pass("gcloud_executable", "gcloud executable is available")
                } else {
                    DoctorCheck::fail(
                        "gcloud_executable",
                        "gcloud executable could not be located safely",
                    )
                },
            );
        }
        match GcpLocalStatus::new(&self.home).observe(profile) {
            Ok(observations) => append_gcp_observation_checks(&mut checks, &observations),
            Err(_) => checks.push(DoctorCheck::fail(
                "gcp_selection",
                "GCP selection metadata could not be inspected safely",
            )),
        }
        checks.push(DoctorCheck::warning(
            "session_continuity",
            "the native gcloud or ADC child owns Credential renewal; authmux cannot classify child expiration safely",
        ));
        DoctorResult {
            context: context_name.to_owned(),
            provider_contacted: false,
            checks,
        }
    }
}

impl<R> SshDoctor<R>
where
    R: ProbeRunner,
{
    #[must_use]
    pub fn new(runner: R) -> Self {
        Self { runner }
    }

    #[must_use]
    pub fn diagnose(&self, context_name: &str, profile: &SshProviderDefinition) -> DoctorResult {
        let configuration =
            if profile.host_alias().is_empty() || profile.expected_remote_principal().is_empty() {
                DoctorCheck::fail("configuration", "SSH Provider Profile is incomplete")
            } else {
                DoctorCheck::pass(
                    "configuration",
                    "SSH host alias and Expected Identity resolved",
                )
            };
        let openssh = match SshClientReadinessCheck::new(&self.runner).observe() {
            Ok(readiness) => DoctorCheck::pass(
                "openssh_client",
                format!("{} is supported", readiness.client_version()),
            ),
            Err(_) => DoctorCheck::fail(
                "openssh_client",
                "OpenSSH client readiness could not be established",
            ),
        };
        let checks = vec![
            configuration,
            openssh,
            DoctorCheck::warning(
                "session_continuity",
                "OpenSSH transport reuse is not Credential renewal and may lapse independently",
            ),
            DoctorCheck::warning(
                "ssh_remote_session",
                "remote identity, authorization, MFA state, Session Usability, and expiry were not observed",
            ),
        ];
        DoctorResult {
            context: context_name.to_owned(),
            provider_contacted: false,
            checks,
        }
    }
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
            DoctorCheck::warning(
                "session_continuity",
                "native AWS execution may renew Credentials, but the parent Session lifetime is not observed",
            ),
        ];
        DoctorResult {
            context: context.name().to_owned(),
            provider_contacted: false,
            checks,
        }
    }
}

fn observe_github_version<R>(runner: &R, profile: &GithubProviderDefinition) -> DoctorCheck
where
    R: ProbeRunner,
{
    let Ok(command) = CommandSpec::new("gh", ["--version"]) else {
        return DoctorCheck::fail("gh_cli", "GitHub CLI command could not be constructed");
    };
    let Ok(output) = runner.probe(
        &command,
        &profile.execution_selection(),
        ProbePolicy::bounded(Duration::from_secs(2), 4_096),
    ) else {
        return DoctorCheck::fail("gh_cli", "GitHub CLI could not be executed safely");
    };
    if output.exit_code() != 0 || output.was_truncated() {
        return DoctorCheck::fail("gh_cli", "GitHub CLI version could not be established");
    }
    let Ok(text) = str::from_utf8(output.stdout()) else {
        return DoctorCheck::fail("gh_cli", "GitHub CLI returned malformed version output");
    };
    let Some(version) = text
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("gh version "))
        .and_then(|remainder| remainder.split_whitespace().next())
        .filter(|version| version.starts_with("2."))
    else {
        return DoctorCheck::fail("gh_cli", "GitHub CLI v2 is required");
    };
    DoctorCheck::pass("gh_cli", format!("GitHub CLI {version} is supported"))
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

#[cfg(unix)]
fn gcloud_executable_available(search_path: Option<&OsStr>) -> bool {
    let Some(search_path) = search_path else {
        return false;
    };
    std::env::split_paths(search_path).any(|directory| {
        if directory.as_os_str().is_empty() {
            return false;
        }
        let candidate = directory.join("gcloud");
        let Ok(candidate) = fs::canonicalize(candidate) else {
            return false;
        };
        fs::metadata(candidate).is_ok_and(|metadata| {
            metadata.is_file()
                && metadata.permissions().mode() & 0o111 != 0
                && metadata.permissions().mode() & 0o022 == 0
        })
    })
}

#[cfg(unix)]
fn append_gcp_observation_checks(
    checks: &mut Vec<DoctorCheck>,
    observations: &[GcpPlaneObservation],
) {
    for observation in observations {
        match observation.plane() {
            GcpCredentialPlane::GcloudCli => append_gcloud_checks(checks, observation),
            GcpCredentialPlane::Adc => checks.push(match observation.status().reason() {
                Some(ObservationReason::InsufficientEvidence) => {
                    DoctorCheck::pass("adc_selector", "ADC credential-file selector is available")
                }
                Some(ObservationReason::Missing) => {
                    DoctorCheck::fail("adc_selector", "ADC credential-file selector is missing")
                }
                _ => DoctorCheck::fail(
                    "adc_selector",
                    "ADC credential-file selector is not protected",
                ),
            }),
        }
    }
}

#[cfg(unix)]
fn append_gcloud_checks(checks: &mut Vec<DoctorCheck>, observation: &GcpPlaneObservation) {
    checks.push(match observation.status().identity_match() {
        IdentityMatch::Match => {
            DoctorCheck::pass("gcloud_identity", "local gcloud identity matches")
        }
        IdentityMatch::Mismatch => {
            DoctorCheck::fail("gcloud_identity", "local gcloud identity does not match")
        }
        IdentityMatch::Unverified
            if observation.status().reason() == Some(ObservationReason::ProviderError) =>
        {
            DoctorCheck::fail("gcloud_identity", "gcloud selection metadata is unsafe")
        }
        IdentityMatch::Unverified => DoctorCheck::warning(
            "gcloud_identity",
            "gcloud selection has no supported local identity metadata",
        ),
    });
    if let Some(source_match) = observation.source_identity_match() {
        checks.push(match source_match {
            IdentityMatch::Match => DoctorCheck::pass(
                "gcloud_source_identity",
                "local gcloud source identity matches",
            ),
            IdentityMatch::Mismatch => DoctorCheck::fail(
                "gcloud_source_identity",
                "local gcloud source identity does not match",
            ),
            IdentityMatch::Unverified => DoctorCheck::warning(
                "gcloud_source_identity",
                "local gcloud source identity was not observed",
            ),
        });
    }
    match observation.project_match() {
        GcpProjectMatch::Match => checks.push(DoctorCheck::pass(
            "gcloud_project",
            "local gcloud project matches",
        )),
        GcpProjectMatch::Mismatch => checks.push(DoctorCheck::fail(
            "gcloud_project",
            "local gcloud project does not match",
        )),
        GcpProjectMatch::Unverified => checks.push(DoctorCheck::warning(
            "gcloud_project",
            "local gcloud project was not observed",
        )),
        GcpProjectMatch::NotApplicable => {}
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

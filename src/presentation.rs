use std::error::Error;
use std::fmt::{self, Write as _};
use std::time::UNIX_EPOCH;

use serde::Serialize;

use crate::{
    AuthenticationContext, ContextDefinition, DoctorOutcome, DoctorResult, EvidenceLevel,
    IdentityMatch, ObservationReason, ReauthenticationNeed, SessionUsability, StatusObservation,
};
#[cfg(unix)]
use crate::{
    GcpCredentialPlane, GcpPlaneObservation, GcpProjectMatch, GcpProviderDefinition,
    GithubProviderDefinition, SshProviderDefinition, SshTransportObservation, SshTransportReuse,
};

const STATUS_SCHEMA_VERSION: u32 = 3;
const CONTEXT_LIST_SCHEMA_VERSION: u32 = 2;
const DOCTOR_SCHEMA_VERSION: u32 = 1;
const ALL_STATUS_SCHEMA_VERSION: u32 = 1;

pub struct StatusReport {
    context: String,
    observations: Vec<StatusEntry>,
}

pub struct AllStatusReport {
    configured_context_count: usize,
    reports: Vec<StatusReport>,
}

pub struct ContextListReport {
    contexts: Vec<ContextListEntry>,
}

pub struct DoctorReport {
    context: String,
    result: &'static str,
    provider_contacted: bool,
    checks: Vec<DoctorReportCheck>,
}

#[derive(Serialize)]
struct DoctorDocument<'a> {
    schema_version: u32,
    command: &'static str,
    context: &'a str,
    result: &'static str,
    provider_contacted: bool,
    checks: &'a [DoctorReportCheck],
}

#[derive(Serialize)]
struct DoctorReportCheck {
    id: &'static str,
    outcome: &'static str,
    summary: String,
}

#[derive(Serialize)]
struct ContextListDocument<'a> {
    schema_version: u32,
    command: &'static str,
    contexts: &'a [ContextListEntry],
}

#[derive(Serialize)]
struct ContextListEntry {
    name: String,
    description: Option<String>,
    providers: Vec<ProviderReference>,
}

#[derive(Serialize)]
struct ProviderReference {
    provider: &'static str,
    credential_plane: Option<&'static str>,
    profile: String,
    expected_identity: String,
}

#[derive(Serialize)]
struct StatusDocument<'a> {
    schema_version: u32,
    command: &'static str,
    context: &'a str,
    observations: &'a [StatusEntry],
}

#[derive(Serialize)]
struct AllStatusDocument<'a> {
    schema_version: u32,
    command: &'static str,
    contexts: Vec<AllStatusContext<'a>>,
}

#[derive(Serialize)]
struct AllStatusContext<'a> {
    context: &'a str,
    observations: &'a [StatusEntry],
}

#[derive(Serialize)]
struct StatusEntry {
    provider: &'static str,
    credential_plane: Option<&'static str>,
    profile: String,
    expected_identity: String,
    observed_identity: Option<String>,
    identity_match: &'static str,
    expected_source_identity: Option<String>,
    observed_source_identity: Option<String>,
    source_identity_match: Option<&'static str>,
    expected_project: Option<String>,
    observed_project: Option<String>,
    project_match: Option<&'static str>,
    session_usability: &'static str,
    reason: &'static str,
    reauthentication_need: &'static str,
    evidence_level: &'static str,
    provider_contacted: bool,
    transport_reuse: Option<&'static str>,
    observed_at_unix: u64,
}

impl StatusReport {
    /// Builds the presentation-safe report for a local AWS Status Observation.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure if the observation time cannot be represented
    /// in the versioned output schema.
    pub fn local_aws(
        context: &AuthenticationContext,
        observation: &StatusObservation,
    ) -> Result<Self, PresentationFailure> {
        let observed_at_unix = observation
            .observed_at()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PresentationFailure::new("status observation time is invalid"))?
            .as_secs();

        Ok(Self {
            context: context.name().to_owned(),
            observations: vec![StatusEntry {
                provider: "aws",
                credential_plane: None,
                profile: context.provider_profile().to_owned(),
                expected_identity: context.expected_account().to_owned(),
                observed_identity: observation
                    .observed_identity()
                    .map(|identity| identity.account().to_owned()),
                identity_match: identity_match(observation.identity_match()),
                expected_source_identity: None,
                observed_source_identity: None,
                source_identity_match: None,
                expected_project: None,
                observed_project: None,
                project_match: None,
                session_usability: session_usability(observation.usability()),
                reason: observation_reason(observation.reason()),
                reauthentication_need: reauthentication_need(observation.reauthentication_need()),
                evidence_level: evidence_level(observation.evidence_level()),
                provider_contacted: false,
                transport_reuse: None,
                observed_at_unix,
            }],
        })
    }

    /// Builds a presentation-safe report for local SSH transport reuse.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure if the observation time cannot be represented
    /// in the versioned output schema.
    #[cfg(unix)]
    pub fn local_ssh(
        context_name: &str,
        profile: &SshProviderDefinition,
        observation: &SshTransportObservation,
    ) -> Result<Self, PresentationFailure> {
        let observed_at_unix = observation
            .observed_at()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PresentationFailure::new("status observation time is invalid"))?
            .as_secs();
        let reason = match observation.transport_reuse() {
            SshTransportReuse::Active | SshTransportReuse::Inactive => "insufficient_evidence",
            SshTransportReuse::Unknown => "provider_error",
        };

        Ok(Self {
            context: context_name.to_owned(),
            observations: vec![StatusEntry {
                provider: "ssh",
                credential_plane: None,
                profile: profile.host_alias().to_owned(),
                expected_identity: profile.expected_remote_principal().to_owned(),
                observed_identity: None,
                identity_match: "unverified",
                expected_source_identity: None,
                observed_source_identity: None,
                source_identity_match: None,
                expected_project: None,
                observed_project: None,
                project_match: None,
                session_usability: "indeterminate",
                reason,
                reauthentication_need: "unknown",
                evidence_level: "local_metadata",
                provider_contacted: observation.provider_contacted(),
                transport_reuse: Some(ssh_transport_reuse(observation.transport_reuse())),
                observed_at_unix,
            }],
        })
    }

    /// Builds a presentation-safe report for independent local GCP planes.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure if an observation cannot be represented or
    /// does not correspond to a configured plane.
    #[cfg(unix)]
    pub fn local_gcp(
        context_name: &str,
        profile: &GcpProviderDefinition,
        observations: &[GcpPlaneObservation],
    ) -> Result<Self, PresentationFailure> {
        let observations = observations
            .iter()
            .map(|observation| gcp_status_entry(profile, observation))
            .collect::<Result<Vec<_>, _>>()?;
        if observations.is_empty() {
            return Err(PresentationFailure::new(
                "GCP status did not contain a credential plane",
            ));
        }
        Ok(Self {
            context: context_name.to_owned(),
            observations,
        })
    }

    /// Builds a presentation-safe report from GitHub CLI provider validation.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure if the observation time cannot be represented.
    #[cfg(unix)]
    pub fn github(
        context_name: &str,
        profile: &GithubProviderDefinition,
        observation: &StatusObservation,
    ) -> Result<Self, PresentationFailure> {
        let observed_at_unix = observation
            .observed_at()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PresentationFailure::new("status observation time is invalid"))?
            .as_secs();
        Ok(Self {
            context: context_name.to_owned(),
            observations: vec![StatusEntry {
                provider: "github",
                credential_plane: None,
                profile: profile.hostname().to_owned(),
                expected_identity: profile.expected_login().to_owned(),
                observed_identity: observation
                    .observed_identity()
                    .map(|identity| identity.value().to_owned()),
                identity_match: identity_match(observation.identity_match()),
                expected_source_identity: None,
                observed_source_identity: None,
                source_identity_match: None,
                expected_project: None,
                observed_project: None,
                project_match: None,
                session_usability: session_usability(observation.usability()),
                reason: observation_reason(observation.reason()),
                reauthentication_need: reauthentication_need(observation.reauthentication_need()),
                evidence_level: evidence_level(observation.evidence_level()),
                provider_contacted: true,
                transport_reuse: None,
                observed_at_unix,
            }],
        })
    }

    #[must_use]
    pub fn render_human(&self) -> String {
        let mut report = String::new();
        writeln!(report, "context: {}", self.context).expect("writing to a String cannot fail");
        for (index, entry) in self.observations.iter().enumerate() {
            if index > 0 {
                writeln!(report).expect("writing to a String cannot fail");
            }
            render_status_entry(&mut report, entry);
        }
        report
    }

    /// Serializes the stable status schema without terminal styling.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure if the fixed report structure cannot be
    /// serialized.
    pub fn render_json(&self) -> Result<String, PresentationFailure> {
        let document = StatusDocument {
            schema_version: STATUS_SCHEMA_VERSION,
            command: "status",
            context: &self.context,
            observations: &self.observations,
        };
        let mut json = serde_json::to_string_pretty(&document)
            .map_err(|_| PresentationFailure::new("could not serialize status report"))?;
        json.push('\n');
        Ok(json)
    }
}

impl AllStatusReport {
    #[must_use]
    pub fn new(configured_context_count: usize, reports: Vec<StatusReport>) -> Self {
        Self {
            configured_context_count,
            reports,
        }
    }

    #[must_use]
    pub fn render_human(&self) -> String {
        let context_count = self.configured_context_count;
        let mut rendered = format!(
            "authentication status: {context_count} context{}\n",
            if context_count == 1 { "" } else { "s" }
        );
        for report in &self.reports {
            rendered.push('\n');
            rendered.push_str(&report.render_human());
        }
        rendered
    }

    /// Serializes all successful provider observations into a stable schema.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure if the fixed report cannot be serialized.
    pub fn render_json(&self) -> Result<String, PresentationFailure> {
        let document = AllStatusDocument {
            schema_version: ALL_STATUS_SCHEMA_VERSION,
            command: "status_all",
            contexts: self
                .reports
                .iter()
                .map(|report| AllStatusContext {
                    context: &report.context,
                    observations: &report.observations,
                })
                .collect(),
        };
        let mut json = serde_json::to_string_pretty(&document)
            .map_err(|_| PresentationFailure::new("could not serialize all-status report"))?;
        json.push('\n');
        Ok(json)
    }
}

fn render_status_entry(report: &mut String, entry: &StatusEntry) {
    writeln!(report, "provider: {}", entry.provider).expect("writing to a String cannot fail");
    if let Some(plane) = entry.credential_plane {
        writeln!(report, "credential plane: {plane}").expect("writing to a String cannot fail");
    }
    writeln!(report, "profile: {}", entry.profile).expect("writing to a String cannot fail");
    writeln!(report, "expected identity: {}", entry.expected_identity)
        .expect("writing to a String cannot fail");
    writeln!(
        report,
        "observed identity: {}",
        entry.observed_identity.as_deref().unwrap_or("not observed")
    )
    .expect("writing to a String cannot fail");
    writeln!(report, "identity match: {}", entry.identity_match)
        .expect("writing to a String cannot fail");
    if let Some(expected) = &entry.expected_source_identity {
        writeln!(report, "expected source identity: {expected}")
            .expect("writing to a String cannot fail");
        writeln!(
            report,
            "observed source identity: {}",
            entry
                .observed_source_identity
                .as_deref()
                .unwrap_or("not observed")
        )
        .expect("writing to a String cannot fail");
        writeln!(
            report,
            "source identity match: {}",
            entry.source_identity_match.unwrap_or("unverified")
        )
        .expect("writing to a String cannot fail");
    }
    if let Some(expected) = &entry.expected_project {
        writeln!(report, "expected project: {expected}").expect("writing to a String cannot fail");
        writeln!(
            report,
            "observed project: {}",
            entry.observed_project.as_deref().unwrap_or("not observed")
        )
        .expect("writing to a String cannot fail");
        writeln!(
            report,
            "project match: {}",
            entry.project_match.unwrap_or("unverified")
        )
        .expect("writing to a String cannot fail");
    }
    writeln!(report, "session usability: {}", entry.session_usability)
        .expect("writing to a String cannot fail");
    writeln!(report, "reason: {}", entry.reason).expect("writing to a String cannot fail");
    writeln!(
        report,
        "reauthentication need: {}",
        entry.reauthentication_need
    )
    .expect("writing to a String cannot fail");
    writeln!(report, "evidence level: {}", entry.evidence_level)
        .expect("writing to a String cannot fail");
    writeln!(
        report,
        "provider contacted: {}",
        if entry.provider_contacted {
            "yes"
        } else {
            "no"
        }
    )
    .expect("writing to a String cannot fail");
    if let Some(transport_reuse) = entry.transport_reuse {
        writeln!(report, "transport reuse: {transport_reuse}")
            .expect("writing to a String cannot fail");
    }
    writeln!(report, "observed at unix: {}", entry.observed_at_unix)
        .expect("writing to a String cannot fail");
}

#[cfg(unix)]
fn gcp_status_entry(
    profile: &GcpProviderDefinition,
    observation: &GcpPlaneObservation,
) -> Result<StatusEntry, PresentationFailure> {
    let status = observation.status();
    let observed_at_unix = status
        .observed_at()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PresentationFailure::new("status observation time is invalid"))?
        .as_secs();
    let (plane, native_profile, expected_identity, expected_source, expected_project) =
        match observation.plane() {
            GcpCredentialPlane::GcloudCli => {
                let gcloud = profile.gcloud().ok_or_else(|| {
                    PresentationFailure::new("GCP status plane is not configured")
                })?;
                (
                    "gcloud_cli",
                    gcloud.configuration().to_owned(),
                    gcloud.expected_principal().to_owned(),
                    gcloud.expected_source_account().map(str::to_owned),
                    gcloud.expected_project().map(str::to_owned),
                )
            }
            GcpCredentialPlane::Adc => {
                let adc = profile.adc().ok_or_else(|| {
                    PresentationFailure::new("GCP status plane is not configured")
                })?;
                (
                    "adc",
                    "credential_file".to_owned(),
                    adc.expected_principal().to_owned(),
                    None,
                    None,
                )
            }
        };
    Ok(StatusEntry {
        provider: "gcp",
        credential_plane: Some(plane),
        profile: native_profile,
        expected_identity,
        observed_identity: status
            .observed_identity()
            .map(|identity| identity.value().to_owned()),
        identity_match: identity_match(status.identity_match()),
        expected_source_identity: expected_source,
        observed_source_identity: observation.observed_source_identity().map(str::to_owned),
        source_identity_match: observation.source_identity_match().map(identity_match),
        expected_project,
        observed_project: observation.observed_project().map(str::to_owned),
        project_match: gcp_project_match(observation.project_match()),
        session_usability: session_usability(status.usability()),
        reason: observation_reason(status.reason()),
        reauthentication_need: reauthentication_need(status.reauthentication_need()),
        evidence_level: evidence_level(status.evidence_level()),
        provider_contacted: observation.provider_contacted(),
        transport_reuse: None,
        observed_at_unix,
    })
}

impl ContextListReport {
    #[must_use]
    pub fn new(definitions: &[ContextDefinition]) -> Self {
        let contexts = definitions
            .iter()
            .map(|definition| {
                let mut providers = Vec::new();
                if let Some(context) = definition.aws() {
                    providers.push(ProviderReference {
                        provider: "aws",
                        credential_plane: None,
                        profile: context.provider_profile().to_owned(),
                        expected_identity: context.expected_account().to_owned(),
                    });
                }
                if let Some(ssh) = definition.ssh() {
                    providers.push(ProviderReference {
                        provider: "ssh",
                        credential_plane: None,
                        profile: ssh.host_alias().to_owned(),
                        expected_identity: ssh.expected_remote_principal().to_owned(),
                    });
                }
                if let Some(gcp) = definition.gcp() {
                    if let Some(gcloud) = gcp.gcloud() {
                        providers.push(ProviderReference {
                            provider: "gcp",
                            credential_plane: Some("gcloud_cli"),
                            profile: gcloud.configuration().to_owned(),
                            expected_identity: gcloud.expected_principal().to_owned(),
                        });
                    }
                    if let Some(adc) = gcp.adc() {
                        providers.push(ProviderReference {
                            provider: "gcp",
                            credential_plane: Some("adc"),
                            profile: "credential_file".to_owned(),
                            expected_identity: adc.expected_principal().to_owned(),
                        });
                    }
                }
                if let Some(github) = definition.github() {
                    providers.push(ProviderReference {
                        provider: "github",
                        credential_plane: None,
                        profile: github.hostname().to_owned(),
                        expected_identity: github.expected_login().to_owned(),
                    });
                }
                ContextListEntry {
                    name: definition.name().to_owned(),
                    description: definition.description().map(str::to_owned),
                    providers,
                }
            })
            .collect();
        Self { contexts }
    }

    #[must_use]
    pub fn render_human(&self) -> String {
        let mut report = String::new();
        writeln!(report, "contexts: {}", self.contexts.len())
            .expect("writing to a String cannot fail");
        for context in &self.contexts {
            writeln!(report, "- {}", context.name).expect("writing to a String cannot fail");
            writeln!(
                report,
                "  description: {}",
                context.description.as_deref().unwrap_or("(none)")
            )
            .expect("writing to a String cannot fail");
            for provider in &context.providers {
                match provider.provider {
                    "aws" => {
                        writeln!(report, "  aws profile: {}", provider.profile)
                            .expect("writing to a String cannot fail");
                        writeln!(
                            report,
                            "  expected AWS account: {}",
                            provider.expected_identity
                        )
                        .expect("writing to a String cannot fail");
                    }
                    "ssh" => {
                        writeln!(report, "  ssh host alias: {}", provider.profile)
                            .expect("writing to a String cannot fail");
                        writeln!(
                            report,
                            "  expected SSH remote principal: {}",
                            provider.expected_identity
                        )
                        .expect("writing to a String cannot fail");
                    }
                    "gcp" if provider.credential_plane == Some("gcloud_cli") => {
                        writeln!(report, "  gcloud configuration: {}", provider.profile)
                            .expect("writing to a String cannot fail");
                        writeln!(
                            report,
                            "  expected gcloud identity: {}",
                            provider.expected_identity
                        )
                        .expect("writing to a String cannot fail");
                    }
                    "gcp" if provider.credential_plane == Some("adc") => {
                        writeln!(report, "  ADC mode: {}", provider.profile)
                            .expect("writing to a String cannot fail");
                        writeln!(
                            report,
                            "  expected ADC identity: {}",
                            provider.expected_identity
                        )
                        .expect("writing to a String cannot fail");
                    }
                    "github" => {
                        writeln!(report, "  GitHub hostname: {}", provider.profile)
                            .expect("writing to a String cannot fail");
                        writeln!(
                            report,
                            "  expected GitHub login: {}",
                            provider.expected_identity
                        )
                        .expect("writing to a String cannot fail");
                    }
                    _ => unreachable!("only typed providers enter context reports"),
                }
            }
            writeln!(report, "  provider state: not observed")
                .expect("writing to a String cannot fail");
        }
        report
    }

    /// Serializes the stable context-list schema without observing providers.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure if the fixed report structure cannot be
    /// serialized.
    pub fn render_json(&self) -> Result<String, PresentationFailure> {
        let document = ContextListDocument {
            schema_version: CONTEXT_LIST_SCHEMA_VERSION,
            command: "context_list",
            contexts: &self.contexts,
        };
        let mut json = serde_json::to_string_pretty(&document)
            .map_err(|_| PresentationFailure::new("could not serialize context list"))?;
        json.push('\n');
        Ok(json)
    }
}

impl DoctorReport {
    #[must_use]
    pub fn new(result: &DoctorResult) -> Self {
        Self {
            context: result.context().to_owned(),
            result: doctor_outcome(result.outcome()),
            provider_contacted: result.provider_contacted(),
            checks: result
                .checks()
                .iter()
                .map(|check| DoctorReportCheck {
                    id: check.id(),
                    outcome: doctor_outcome(check.outcome()),
                    summary: check.summary().to_owned(),
                })
                .collect(),
        }
    }

    #[must_use]
    pub fn render_human(&self) -> String {
        let mut report = String::new();
        writeln!(report, "doctor: {}", self.context).expect("writing to a String cannot fail");
        writeln!(report, "result: {}", self.result).expect("writing to a String cannot fail");
        writeln!(
            report,
            "provider contacted: {}",
            if self.provider_contacted { "yes" } else { "no" }
        )
        .expect("writing to a String cannot fail");
        writeln!(report, "checks: {}", self.checks.len()).expect("writing to a String cannot fail");
        for check in &self.checks {
            writeln!(
                report,
                "- [{}] {}: {}",
                check.outcome, check.id, check.summary
            )
            .expect("writing to a String cannot fail");
        }
        report
    }

    /// Serializes the stable doctor schema without provider output.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure if the fixed report structure cannot be
    /// serialized.
    pub fn render_json(&self) -> Result<String, PresentationFailure> {
        let document = DoctorDocument {
            schema_version: DOCTOR_SCHEMA_VERSION,
            command: "doctor",
            context: &self.context,
            result: self.result,
            provider_contacted: self.provider_contacted,
            checks: &self.checks,
        };
        let mut json = serde_json::to_string_pretty(&document)
            .map_err(|_| PresentationFailure::new("could not serialize doctor report"))?;
        json.push('\n');
        Ok(json)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresentationFailure {
    message: &'static str,
}

impl PresentationFailure {
    fn new(message: &'static str) -> Self {
        Self { message }
    }
}

impl fmt::Display for PresentationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl Error for PresentationFailure {}

const fn identity_match(value: IdentityMatch) -> &'static str {
    match value {
        IdentityMatch::Match => "match",
        IdentityMatch::Mismatch => "mismatch",
        IdentityMatch::Unverified => "unverified",
    }
}

#[cfg(unix)]
const fn gcp_project_match(value: GcpProjectMatch) -> Option<&'static str> {
    match value {
        GcpProjectMatch::Match => Some("match"),
        GcpProjectMatch::Mismatch => Some("mismatch"),
        GcpProjectMatch::Unverified => Some("unverified"),
        GcpProjectMatch::NotApplicable => None,
    }
}

const fn session_usability(value: SessionUsability) -> &'static str {
    match value {
        SessionUsability::Usable => "usable",
        SessionUsability::Unusable => "unusable",
        SessionUsability::Indeterminate => "indeterminate",
    }
}

const fn observation_reason(value: Option<ObservationReason>) -> &'static str {
    match value {
        Some(ObservationReason::Expired) => "expired",
        Some(ObservationReason::Missing) => "missing",
        Some(ObservationReason::Unreachable) => "unreachable",
        Some(ObservationReason::ProviderError) => "provider_error",
        Some(ObservationReason::InsufficientEvidence) => "insufficient_evidence",
        None => "none",
    }
}

const fn reauthentication_need(value: ReauthenticationNeed) -> &'static str {
    match value {
        ReauthenticationNeed::Required => "required",
        ReauthenticationNeed::NotRequired => "not_required",
        ReauthenticationNeed::Unknown => "unknown",
        ReauthenticationNeed::NotApplicable => "not_applicable",
    }
}

const fn evidence_level(value: EvidenceLevel) -> &'static str {
    match value {
        EvidenceLevel::LocalMetadata => "local_metadata",
        EvidenceLevel::ProviderValidation => "provider_validation",
        EvidenceLevel::ConnectivityOnly => "connectivity_only",
    }
}

const fn doctor_outcome(value: DoctorOutcome) -> &'static str {
    match value {
        DoctorOutcome::Pass => "pass",
        DoctorOutcome::Warning => "warning",
        DoctorOutcome::Fail => "fail",
    }
}

#[cfg(unix)]
const fn ssh_transport_reuse(value: SshTransportReuse) -> &'static str {
    match value {
        SshTransportReuse::Active => "active",
        SshTransportReuse::Inactive => "inactive",
        SshTransportReuse::Unknown => "unknown",
    }
}

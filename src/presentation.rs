use std::error::Error;
use std::fmt::{self, Write as _};
use std::time::UNIX_EPOCH;

use serde::Serialize;

use crate::{
    AuthenticationContext, ContextDefinition, DoctorOutcome, DoctorResult, EvidenceLevel,
    IdentityMatch, ObservationReason, ReauthenticationNeed, SessionUsability, StatusObservation,
};

const STATUS_SCHEMA_VERSION: u32 = 1;
const CONTEXT_LIST_SCHEMA_VERSION: u32 = 1;
const DOCTOR_SCHEMA_VERSION: u32 = 1;

pub struct StatusReport {
    context: String,
    observation: StatusEntry,
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
    profile: String,
    expected_identity: String,
}

#[derive(Serialize)]
struct StatusDocument<'a> {
    schema_version: u32,
    command: &'static str,
    context: &'a str,
    observations: [&'a StatusEntry; 1],
}

#[derive(Serialize)]
struct StatusEntry {
    provider: &'static str,
    profile: String,
    expected_identity: String,
    observed_identity: Option<String>,
    identity_match: &'static str,
    session_usability: &'static str,
    reason: &'static str,
    reauthentication_need: &'static str,
    evidence_level: &'static str,
    provider_contacted: bool,
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
            observation: StatusEntry {
                provider: "aws",
                profile: context.provider_profile().to_owned(),
                expected_identity: context.expected_account().to_owned(),
                observed_identity: observation
                    .observed_identity()
                    .map(|identity| identity.account().to_owned()),
                identity_match: identity_match(observation.identity_match()),
                session_usability: session_usability(observation.usability()),
                reason: observation_reason(observation.reason()),
                reauthentication_need: reauthentication_need(observation.reauthentication_need()),
                evidence_level: evidence_level(observation.evidence_level()),
                provider_contacted: false,
                observed_at_unix,
            },
        })
    }

    #[must_use]
    pub fn render_human(&self) -> String {
        let entry = &self.observation;
        let mut report = String::new();
        writeln!(report, "context: {}", self.context).expect("writing to a String cannot fail");
        writeln!(report, "provider: {}", entry.provider).expect("writing to a String cannot fail");
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
        writeln!(report, "observed at unix: {}", entry.observed_at_unix)
            .expect("writing to a String cannot fail");
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
            observations: [&self.observation],
        };
        let mut json = serde_json::to_string_pretty(&document)
            .map_err(|_| PresentationFailure::new("could not serialize status report"))?;
        json.push('\n');
        Ok(json)
    }
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
                        profile: context.provider_profile().to_owned(),
                        expected_identity: context.expected_account().to_owned(),
                    });
                }
                if let Some(ssh) = definition.ssh() {
                    providers.push(ProviderReference {
                        provider: "ssh",
                        profile: ssh.host_alias().to_owned(),
                        expected_identity: ssh.expected_remote_principal().to_owned(),
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

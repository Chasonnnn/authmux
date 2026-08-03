use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationContext {
    name: String,
    provider_profile: String,
    expected_account: String,
}

impl AuthenticationContext {
    /// Creates an AWS Authentication Context with a declared Expected Identity.
    ///
    /// # Errors
    ///
    /// Returns a domain failure when a name is empty or the Expected Identity
    /// is not a twelve-digit AWS account identifier.
    pub fn aws(
        name: impl Into<String>,
        provider_profile: impl Into<String>,
        expected_account: impl Into<String>,
    ) -> Result<Self, DomainFailure> {
        let name = required("context name", name.into())?;
        let provider_profile = required("provider profile", provider_profile.into())?;
        let expected_account = aws_account(expected_account.into())?;

        Ok(Self {
            name,
            provider_profile,
            expected_account,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn provider_profile(&self) -> &str {
        &self.provider_profile
    }

    #[must_use]
    pub fn expected_account(&self) -> &str {
        &self.expected_account
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedIdentity {
    account: String,
}

impl ObservedIdentity {
    /// Creates a provider-reported AWS account identity.
    ///
    /// # Errors
    ///
    /// Returns a domain failure unless the account contains exactly 12 digits.
    pub fn aws_account(account: impl Into<String>) -> Result<Self, DomainFailure> {
        Ok(Self {
            account: aws_account(account.into())?,
        })
    }

    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityMatch {
    Match,
    Mismatch,
    Unverified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionUsability {
    Usable,
    Unusable,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationReason {
    Expired,
    Missing,
    Unreachable,
    ProviderError,
    InsufficientEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReauthenticationNeed {
    Required,
    NotRequired,
    Unknown,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceLevel {
    LocalMetadata,
    ProviderValidation,
    ConnectivityOnly,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusObservation {
    observed_identity: ObservedIdentity,
    identity_match: IdentityMatch,
    usability: SessionUsability,
    reason: Option<ObservationReason>,
    reauthentication_need: ReauthenticationNeed,
    evidence_level: EvidenceLevel,
}

impl StatusObservation {
    #[must_use]
    pub fn usable_provider_validation(observed_identity: ObservedIdentity) -> Self {
        Self {
            observed_identity,
            identity_match: IdentityMatch::Unverified,
            usability: SessionUsability::Usable,
            reason: None,
            reauthentication_need: ReauthenticationNeed::NotRequired,
            evidence_level: EvidenceLevel::ProviderValidation,
        }
    }

    #[must_use]
    pub fn unusable(
        observed_identity: ObservedIdentity,
        reason: ObservationReason,
        reauthentication_need: ReauthenticationNeed,
        evidence_level: EvidenceLevel,
    ) -> Self {
        Self {
            observed_identity,
            identity_match: IdentityMatch::Unverified,
            usability: SessionUsability::Unusable,
            reason: Some(reason),
            reauthentication_need,
            evidence_level,
        }
    }

    #[must_use]
    pub fn indeterminate(
        observed_identity: ObservedIdentity,
        reason: ObservationReason,
        reauthentication_need: ReauthenticationNeed,
        evidence_level: EvidenceLevel,
    ) -> Self {
        Self {
            observed_identity,
            identity_match: IdentityMatch::Unverified,
            usability: SessionUsability::Indeterminate,
            reason: Some(reason),
            reauthentication_need,
            evidence_level,
        }
    }

    #[must_use]
    pub fn observed_identity(&self) -> &ObservedIdentity {
        &self.observed_identity
    }

    #[must_use]
    pub fn identity_match(&self) -> IdentityMatch {
        self.identity_match
    }

    #[must_use]
    pub fn usability(&self) -> SessionUsability {
        self.usability
    }

    #[must_use]
    pub fn reason(&self) -> Option<ObservationReason> {
        self.reason
    }

    #[must_use]
    pub fn reauthentication_need(&self) -> ReauthenticationNeed {
        self.reauthentication_need
    }

    #[must_use]
    pub fn evidence_level(&self) -> EvidenceLevel {
        self.evidence_level
    }

    pub(crate) fn compare_to(mut self, expected_account: &str) -> Self {
        self.identity_match = if self.observed_identity.account() == expected_account {
            IdentityMatch::Match
        } else {
            IdentityMatch::Mismatch
        };
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    program: OsString,
    arguments: Vec<OsString>,
}

impl CommandSpec {
    /// Creates a literal program-and-argument-vector command.
    ///
    /// # Errors
    ///
    /// Returns a domain failure when the program is empty.
    pub fn new<I, S>(program: impl Into<OsString>, arguments: I) -> Result<Self, DomainFailure>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let program = program.into();
        if program.is_empty() {
            return Err(DomainFailure::new("command program cannot be empty"));
        }

        Ok(Self {
            program,
            arguments: arguments.into_iter().map(Into::into).collect(),
        })
    }

    #[must_use]
    pub fn program(&self) -> &OsStr {
        &self.program
    }

    #[must_use]
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionSelection {
    environment: Vec<(OsString, OsString)>,
}

impl ExecutionSelection {
    #[must_use]
    pub fn aws_profile(profile: impl Into<OsString>) -> Self {
        Self {
            environment: vec![(OsString::from("AWS_PROFILE"), profile.into())],
        }
    }

    #[must_use]
    pub fn environment(&self) -> &[(OsString, OsString)] {
        &self.environment
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionOutcome {
    exit_code: Option<i32>,
    signal: Option<i32>,
}

impl ExecutionOutcome {
    #[must_use]
    pub fn exited(exit_code: i32) -> Self {
        Self {
            exit_code: Some(exit_code),
            signal: None,
        }
    }

    #[must_use]
    pub fn signaled(signal: i32) -> Self {
        Self {
            exit_code: None,
            signal: Some(signal),
        }
    }

    #[must_use]
    pub fn exit_code(self) -> Option<i32> {
        self.exit_code
    }

    #[must_use]
    pub fn signal(self) -> Option<i32> {
        self.signal
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainFailure {
    message: String,
}

impl DomainFailure {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub(crate) fn public(message: impl Into<String>) -> Self {
        Self::new(message)
    }
}

impl fmt::Display for DomainFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for DomainFailure {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderFailure {
    message: String,
}

impl ProviderFailure {
    #[must_use]
    pub fn sanitized(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl From<DomainFailure> for ProviderFailure {
    fn from(failure: DomainFailure) -> Self {
        Self::sanitized(failure.to_string())
    }
}

impl fmt::Display for ProviderFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ProviderFailure {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionFailure {
    IdentityMismatch {
        expected: String,
        observed: String,
    },
    SessionUnusable {
        reason: ObservationReason,
        reauthentication_need: ReauthenticationNeed,
    },
    SessionIndeterminate {
        reason: ObservationReason,
    },
    Provider(ProviderFailure),
    Process(String),
}

impl fmt::Display for ExecutionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdentityMismatch { expected, observed } => write!(
                formatter,
                "refusing child execution: expected AWS account {expected}, but provider reported {observed}"
            ),
            Self::SessionUnusable {
                reason,
                reauthentication_need,
            } => write!(
                formatter,
                "refusing child execution: session is unusable ({reason:?}); reauthentication is {reauthentication_need:?}"
            ),
            Self::SessionIndeterminate { reason } => write!(
                formatter,
                "refusing child execution: session usability is indeterminate ({reason:?})"
            ),
            Self::Provider(failure) => write!(formatter, "provider observation failed: {failure}"),
            Self::Process(message) => write!(formatter, "child execution failed: {message}"),
        }
    }
}

impl Error for ExecutionFailure {}

impl From<ProviderFailure> for ExecutionFailure {
    fn from(failure: ProviderFailure) -> Self {
        Self::Provider(failure)
    }
}

fn required(label: &str, value: String) -> Result<String, DomainFailure> {
    if value.trim().is_empty() {
        Err(DomainFailure::new(format!("{label} cannot be empty")))
    } else {
        Ok(value)
    }
}

fn aws_account(value: String) -> Result<String, DomainFailure> {
    if value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()) {
        Ok(value)
    } else {
        Err(DomainFailure::new(
            "AWS account identity must contain exactly 12 digits",
        ))
    }
}

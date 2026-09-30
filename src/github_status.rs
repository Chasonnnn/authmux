use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use crate::{
    CommandSpec, ContextDefinition, EvidenceLevel, ExecutionSelection, GithubProviderDefinition,
    IdentityMatch, ObservationReason, ObservedIdentity, ProbePolicy, ProbeRunner, ProviderFailure,
    ReauthenticationNeed, SessionUsability, StatusObservation,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubLoginPlan {
    context_name: String,
    profile: GithubProviderDefinition,
    command: CommandSpec,
}

pub struct GithubExecutionGuard;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubGuardFailure {
    message: String,
    exit_code: i32,
    reauthentication_required: bool,
}

impl GithubLoginPlan {
    /// Builds an explicit native login plan from one resolved GitHub profile.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure when GitHub is absent or the command cannot
    /// be constructed safely.
    pub fn new(definition: &ContextDefinition) -> Result<Self, GithubGuardFailure> {
        let profile = definition.github().ok_or_else(|| {
            GithubGuardFailure::new("GitHub Provider Profile is not configured", 2)
        })?;
        let command = CommandSpec::new(
            "gh",
            [
                "auth",
                "login",
                "--hostname",
                profile.hostname(),
                "--web",
                "--skip-ssh-key",
            ],
        )
        .map_err(|_| GithubGuardFailure::new("GitHub login command is invalid", 2))?;
        Ok(Self {
            context_name: definition.name().to_owned(),
            profile: profile.clone(),
            command,
        })
    }

    #[must_use]
    pub fn context_name(&self) -> &str {
        &self.context_name
    }

    #[must_use]
    pub fn profile(&self) -> &GithubProviderDefinition {
        &self.profile
    }

    #[must_use]
    pub fn command(&self) -> &CommandSpec {
        &self.command
    }

    #[must_use]
    pub fn selection(&self) -> ExecutionSelection {
        self.profile.login_selection()
    }

    /// Verifies that provider intent did not drift after the login preview.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error when the current definition differs.
    pub fn ensure_unchanged(&self, current: &ContextDefinition) -> Result<(), GithubGuardFailure> {
        if current.name() != self.context_name || current.github() != Some(&self.profile) {
            return Err(GithubGuardFailure::new(
                "authentication context changed before child execution; retry the command",
                6,
            ));
        }
        Ok(())
    }
}

impl GithubExecutionGuard {
    /// Requires a GitHub profile for `gh` before another provider can observe
    /// its session or supply the child's selectors.
    ///
    /// # Errors
    ///
    /// Returns a usage failure when `gh` targets a context without GitHub.
    pub fn validate_context(
        command: &CommandSpec,
        definition: &ContextDefinition,
    ) -> Result<(), GithubGuardFailure> {
        if is_gh(command) && definition.github().is_none() {
            return Err(GithubGuardFailure::new(
                "refusing child execution: gh requires a GitHub Provider Profile; select a configured GitHub context with --context (see `authmux context list`)",
                2,
            ));
        }
        Ok(())
    }

    /// Rejects commands whose GitHub authentication is not selected by
    /// `GH_CONFIG_DIR` before any provider contact occurs.
    ///
    /// # Errors
    ///
    /// Returns a usage failure for every non-`gh` child.
    pub fn validate_command(command: &CommandSpec) -> Result<(), GithubGuardFailure> {
        if !is_gh(command) {
            return Err(GithubGuardFailure::new(
                "GitHub execution supports only the gh CLI; raw Git authentication is not selected by GH_CONFIG_DIR",
                2,
            ));
        }
        Ok(())
    }

    /// Converts provider validation into a process-scoped GitHub selection.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for mismatch or unusable evidence.
    pub fn authorize(
        context_name: &str,
        profile: &GithubProviderDefinition,
        observation: &StatusObservation,
    ) -> Result<ExecutionSelection, GithubGuardFailure> {
        if observation.identity_match() == IdentityMatch::Mismatch {
            return Err(GithubGuardFailure::new(
                "refusing child execution: GitHub identity does not match the Expected Identity",
                4,
            ));
        }
        if observation.usability() != SessionUsability::Usable
            && observation.reauthentication_need() == ReauthenticationNeed::Required
        {
            return Err(GithubGuardFailure::reauthentication_required(format!(
                "refusing child execution: GitHub Session is not usable; run `authmux login {context_name} --provider github`"
            )));
        }
        if observation.identity_match() != IdentityMatch::Match {
            return Err(GithubGuardFailure::new(
                "refusing child execution: GitHub identity match could not be established",
                4,
            ));
        }
        if observation.usability() != SessionUsability::Usable {
            return Err(GithubGuardFailure::new(
                "refusing child execution: GitHub Session Usability could not be established",
                1,
            ));
        }
        Ok(profile.execution_selection())
    }

    /// Revalidates the material GitHub profile immediately before spawn.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error when the definition changed.
    pub fn ensure_unchanged(
        original: &ContextDefinition,
        current: &ContextDefinition,
    ) -> Result<(), GithubGuardFailure> {
        if original.name() != current.name() || original.github() != current.github() {
            return Err(GithubGuardFailure::new(
                "authentication context changed before child execution; retry the command",
                6,
            ));
        }
        Ok(())
    }
}

fn is_gh(command: &CommandSpec) -> bool {
    Path::new(command.program())
        .file_name()
        .is_some_and(|name| name == "gh")
}

impl GithubGuardFailure {
    fn new(message: impl Into<String>, exit_code: i32) -> Self {
        Self {
            message: message.into(),
            exit_code,
            reauthentication_required: false,
        }
    }

    fn reauthentication_required(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: 10,
            reauthentication_required: true,
        }
    }

    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        self.exit_code
    }

    #[must_use]
    pub const fn requires_reauthentication(&self) -> bool {
        self.reauthentication_required
    }
}

impl fmt::Display for GithubGuardFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for GithubGuardFailure {}

pub struct GithubStatus<R> {
    runner: R,
}

impl<R> GithubStatus<R>
where
    R: ProbeRunner,
{
    #[must_use]
    pub fn new(runner: R) -> Self {
        Self { runner }
    }

    /// Contacts GitHub through the selected native CLI configuration and
    /// returns only the active login and normalized Session state.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure when the bounded provider response is
    /// malformed, ambiguous, truncated, or backed by insecure token storage.
    pub fn observe(
        &self,
        profile: &GithubProviderDefinition,
    ) -> Result<StatusObservation, ProviderFailure> {
        let command = CommandSpec::new(
            "gh",
            [
                "auth",
                "status",
                "--active",
                "--hostname",
                profile.hostname(),
                "--json",
                "hosts",
            ],
        )?;
        let output = self.runner.probe(
            &command,
            &profile.execution_selection(),
            ProbePolicy::bounded(Duration::from_secs(10), 16_384),
        )?;
        if output.was_truncated() {
            return Err(ProviderFailure::sanitized(
                "GitHub status exceeded the safe output limit",
            ));
        }
        if output.exit_code() != 0 {
            return Err(ProviderFailure::sanitized(
                "GitHub status failed; run `authmux login` for this context",
            ));
        }

        let document: GithubStatusDocument = serde_json::from_slice(output.stdout())
            .map_err(|_| ProviderFailure::sanitized("GitHub returned malformed status output"))?;
        let Some(accounts) = document.hosts.get(profile.hostname()) else {
            return Ok(StatusObservation::indeterminate_without_identity(
                ObservationReason::Missing,
                ReauthenticationNeed::Required,
                EvidenceLevel::ProviderValidation,
            ));
        };
        let active = accounts
            .iter()
            .filter(|account| account.active && account.host == profile.hostname())
            .collect::<Vec<_>>();
        let [account] = active.as_slice() else {
            return Err(ProviderFailure::sanitized(
                "GitHub returned an ambiguous active account",
            ));
        };
        if account.token_source != "keyring" {
            return Err(ProviderFailure::sanitized(
                "GitHub credential is not stored in the system credential store",
            ));
        }
        let identity = ObservedIdentity::provider_identity(account.login.clone())?;
        let observation = if account.state == "success" {
            StatusObservation::usable_provider_validation(identity)
        } else {
            StatusObservation::unusable(
                identity,
                ObservationReason::ProviderError,
                ReauthenticationNeed::Required,
                EvidenceLevel::ProviderValidation,
            )
        };
        Ok(observation.compare_to(profile.expected_login()))
    }
}

#[derive(Deserialize)]
struct GithubStatusDocument {
    hosts: BTreeMap<String, Vec<GithubAccount>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GithubAccount {
    state: String,
    active: bool,
    host: String,
    login: String,
    token_source: String,
}

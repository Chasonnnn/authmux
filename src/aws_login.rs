use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::str;
use std::time::Duration;

use crate::{
    AuthenticationContext, CommandSpec, ContextDefinition, ExecutionSelection, ProbePolicy,
    ProbeRunner, aws_adapter::login_session_account,
};

/// Discovers the supported native reauthentication command for an AWS profile.
pub struct AwsLoginPlanner<R> {
    runner: R,
}

impl<R> AwsLoginPlanner<R> {
    #[must_use]
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl<R> AwsLoginPlanner<R>
where
    R: ProbeRunner,
{
    /// Builds a fail-closed native login plan from documented local metadata.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure when metadata is unsafe, ambiguous, or does
    /// not identify a supported explicit login mode.
    pub fn plan(&self, context: &AuthenticationContext) -> Result<AwsLoginPlan, AwsLoginFailure> {
        let mut profile = context.provider_profile().to_owned();
        let mut visited = Vec::new();

        for depth in 0..8 {
            if visited.iter().any(|candidate| candidate == &profile) {
                return Err(AwsLoginFailure::SourceProfileCycle);
            }
            visited.push(profile.clone());

            let login_session = self.probe_setting(&profile, "login_session")?;
            let sso_account = self.probe_setting(&profile, "sso_account_id")?;
            let role_arn = self.probe_setting(&profile, "role_arn")?;
            let source_profile = self.probe_setting(&profile, "source_profile")?;

            let has_direct_mode = login_session.is_some() || sso_account.is_some();
            let has_role_mode = role_arn.is_some() || source_profile.is_some();
            if (login_session.is_some() && sso_account.is_some())
                || (has_direct_mode && has_role_mode)
            {
                return Err(AwsLoginFailure::AmbiguousProfile);
            }

            if let Some(login_session) = login_session {
                let account = login_session_account(&login_session)
                    .ok_or(AwsLoginFailure::UnsafeProfileMetadata)?;
                if depth == 0 && account != context.expected_account() {
                    return Err(AwsLoginFailure::IdentityMismatch);
                }
                return AwsLoginPlan::new(context, AwsLoginMode::ConsoleLogin, profile);
            }

            if let Some(account) = sso_account {
                if !valid_account(&account) {
                    return Err(AwsLoginFailure::UnsafeProfileMetadata);
                }
                if depth == 0 && account != context.expected_account() {
                    return Err(AwsLoginFailure::IdentityMismatch);
                }
                return AwsLoginPlan::new(context, AwsLoginMode::IdentityCenter, profile);
            }

            match (role_arn, source_profile) {
                (Some(role_arn), Some(source_profile)) => {
                    let account = role_arn_account(&role_arn)
                        .ok_or(AwsLoginFailure::UnsafeProfileMetadata)?;
                    if depth == 0 && account != context.expected_account() {
                        return Err(AwsLoginFailure::IdentityMismatch);
                    }
                    if !valid_profile_name(&source_profile) {
                        return Err(AwsLoginFailure::UnsafeProfileMetadata);
                    }
                    profile = source_profile;
                }
                (None, None) => return Err(AwsLoginFailure::UnsupportedProfile),
                (Some(_), None) | (None, Some(_)) => {
                    return Err(AwsLoginFailure::UnsafeProfileMetadata);
                }
            }
        }

        Err(AwsLoginFailure::SourceProfileDepth)
    }

    fn probe_setting(
        &self,
        profile: &str,
        setting: &str,
    ) -> Result<Option<String>, AwsLoginFailure> {
        let command = CommandSpec::new("aws", ["configure", "get", setting, "--profile", profile])
            .map_err(|_| AwsLoginFailure::InvalidProfile)?;
        let output = self
            .runner
            .probe(
                &command,
                &ExecutionSelection::none(),
                ProbePolicy::bounded(Duration::from_secs(2), 4_096),
            )
            .map_err(|_| AwsLoginFailure::MetadataProbeFailed)?;
        if output.was_truncated() {
            return Err(AwsLoginFailure::UnsafeProfileMetadata);
        }
        if output.exit_code() != 0 {
            return Ok(None);
        }
        let value = str::from_utf8(output.stdout())
            .map_err(|_| AwsLoginFailure::UnsafeProfileMetadata)?
            .trim();
        if value.is_empty() {
            return Err(AwsLoginFailure::UnsafeProfileMetadata);
        }
        Ok(Some(value.to_owned()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsLoginPlan {
    command: CommandSpec,
    selection: ExecutionSelection,
    provider_profile: String,
    expected_account: String,
    login_profile: String,
    mode: AwsLoginMode,
}

impl AwsLoginPlan {
    fn new(
        context: &AuthenticationContext,
        mode: AwsLoginMode,
        login_profile: String,
    ) -> Result<Self, AwsLoginFailure> {
        let arguments = match mode {
            AwsLoginMode::ConsoleLogin => vec![
                OsString::from("login"),
                OsString::from("--profile"),
                OsString::from(&login_profile),
                OsString::from("--no-cli-auto-prompt"),
            ],
            AwsLoginMode::IdentityCenter => vec![
                OsString::from("sso"),
                OsString::from("login"),
                OsString::from("--profile"),
                OsString::from(&login_profile),
                OsString::from("--no-cli-auto-prompt"),
            ],
        };
        let command =
            CommandSpec::new("aws", arguments).map_err(|_| AwsLoginFailure::InvalidProfile)?;
        Ok(Self {
            command,
            selection: ExecutionSelection::aws_profile(&login_profile),
            provider_profile: context.provider_profile().to_owned(),
            expected_account: context.expected_account().to_owned(),
            login_profile,
            mode,
        })
    }

    #[must_use]
    pub fn command(&self) -> &CommandSpec {
        &self.command
    }

    #[must_use]
    pub fn selection(&self) -> &ExecutionSelection {
        &self.selection
    }

    #[must_use]
    pub fn provider_profile(&self) -> &str {
        &self.provider_profile
    }

    #[must_use]
    pub fn expected_account(&self) -> &str {
        &self.expected_account
    }

    #[must_use]
    pub fn login_profile(&self) -> &str {
        &self.login_profile
    }

    #[must_use]
    pub fn mode(&self) -> AwsLoginMode {
        self.mode
    }

    /// Rejects material Authentication Context changes after preview.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure when provider composition or AWS selection
    /// changed before native mutation.
    pub fn ensure_context_unchanged(
        initial: &ContextDefinition,
        current: &ContextDefinition,
    ) -> Result<(), AwsLoginFailure> {
        if initial.name() != current.name()
            || initial.aws() != current.aws()
            || initial.gcp().is_some() != current.gcp().is_some()
            || initial.ssh().is_some() != current.ssh().is_some()
        {
            return Err(AwsLoginFailure::ContextChanged);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AwsLoginMode {
    ConsoleLogin,
    IdentityCenter,
}

impl fmt::Display for AwsLoginMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ConsoleLogin => "console_login",
            Self::IdentityCenter => "iam_identity_center",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AwsLoginFailure {
    MetadataProbeFailed,
    UnsafeProfileMetadata,
    AmbiguousProfile,
    UnsupportedProfile,
    IdentityMismatch,
    InvalidProfile,
    ContextChanged,
    PlanChanged,
    SourceProfileCycle,
    SourceProfileDepth,
}

impl AwsLoginFailure {
    #[must_use]
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::ContextChanged | Self::PlanChanged => 6,
            Self::MetadataProbeFailed
            | Self::UnsafeProfileMetadata
            | Self::AmbiguousProfile
            | Self::UnsupportedProfile
            | Self::IdentityMismatch
            | Self::InvalidProfile
            | Self::SourceProfileCycle
            | Self::SourceProfileDepth => 2,
        }
    }
}

impl fmt::Display for AwsLoginFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MetadataProbeFailed => {
                "refusing AWS login: local profile metadata could not be inspected safely"
            }
            Self::UnsafeProfileMetadata => {
                "refusing AWS login: local profile metadata is malformed or unsafe"
            }
            Self::AmbiguousProfile => {
                "refusing AWS login: the selected profile declares multiple login modes"
            }
            Self::UnsupportedProfile => {
                "refusing AWS login: the selected profile has no supported explicit login mode"
            }
            Self::IdentityMismatch => {
                "refusing AWS login: local profile metadata does not match the Expected Identity"
            }
            Self::InvalidProfile => "refusing AWS login: the selected profile is invalid",
            Self::ContextChanged => {
                "refusing AWS login: authentication context changed after preview; retry the command"
            }
            Self::PlanChanged => {
                "refusing AWS login: native profile metadata changed after preview; retry the command"
            }
            Self::SourceProfileCycle => {
                "refusing AWS login: the native source-profile chain contains a cycle"
            }
            Self::SourceProfileDepth => {
                "refusing AWS login: the native source-profile chain exceeds the safe depth"
            }
        })
    }
}

impl Error for AwsLoginFailure {}

fn valid_account(account: &str) -> bool {
    account.len() == 12 && account.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_profile_name(profile: &str) -> bool {
    !profile.is_empty()
        && profile.len() <= 128
        && profile.trim() == profile
        && profile
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn role_arn_account(role_arn: &str) -> Option<&str> {
    let parts = role_arn.split(':').collect::<Vec<_>>();
    let ["arn", partition, "iam", "", account, resource] = parts.as_slice() else {
        return None;
    };
    (matches!(*partition, "aws" | "aws-us-gov" | "aws-cn")
        && valid_account(account)
        && resource.starts_with("role/")
        && resource.bytes().all(|byte| byte.is_ascii_graphic()))
    .then_some(account)
}

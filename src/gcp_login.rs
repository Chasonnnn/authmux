use std::error::Error;
use std::ffi::OsString;
use std::fmt;

use crate::{CommandSpec, ContextDefinition, ExecutionSelection, GcpProviderDefinition};

/// A fully selected, interactive native gcloud login operation.
pub struct GcpLoginPlan {
    command: CommandSpec,
    selection: ExecutionSelection,
    configuration: String,
    expected_identity: String,
    login_account: String,
}

impl GcpLoginPlan {
    /// Builds the native login command and process-scoped gcloud selectors.
    ///
    /// # Errors
    ///
    /// Fails when the context has no gcloud CLI plane or validated profile
    /// data cannot form the fixed native command.
    pub fn new(profile: &GcpProviderDefinition) -> Result<Self, GcpLoginFailure> {
        let gcloud = profile
            .gcloud()
            .ok_or(GcpLoginFailure::GcloudPlaneRequired)?;
        let login_account = gcloud
            .expected_source_account()
            .unwrap_or_else(|| gcloud.expected_principal())
            .to_owned();
        let command = CommandSpec::new(
            "gcloud",
            [
                OsString::from("auth"),
                OsString::from("login"),
                OsString::from(&login_account),
                OsString::from("--brief"),
                OsString::from("--force"),
            ],
        )
        .map_err(|_| GcpLoginFailure::InvalidProfile)?;
        let selection = ExecutionSelection::from_environment(vec![
            (
                OsString::from("CLOUDSDK_CONFIG"),
                gcloud.config_dir().as_os_str().to_owned(),
            ),
            (
                OsString::from("CLOUDSDK_ACTIVE_CONFIG_NAME"),
                OsString::from(gcloud.configuration()),
            ),
            (
                OsString::from("CLOUDSDK_CORE_DISABLE_FILE_LOGGING"),
                OsString::from("1"),
            ),
            (
                OsString::from("CLOUDSDK_CORE_DISABLE_USAGE_REPORTING"),
                OsString::from("1"),
            ),
            (
                OsString::from("CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK"),
                OsString::from("1"),
            ),
        ]);
        Ok(Self {
            command,
            selection,
            configuration: gcloud.configuration().to_owned(),
            expected_identity: gcloud.expected_principal().to_owned(),
            login_account,
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
    pub fn configuration(&self) -> &str {
        &self.configuration
    }

    #[must_use]
    pub fn expected_identity(&self) -> &str {
        &self.expected_identity
    }

    #[must_use]
    pub fn login_account(&self) -> &str {
        &self.login_account
    }

    /// Revalidates material context fields immediately before native mutation.
    ///
    /// # Errors
    ///
    /// Fails when the context name, GCP profile, or provider composition
    /// changed after the preview.
    pub fn ensure_unchanged(
        initial: &ContextDefinition,
        current: &ContextDefinition,
    ) -> Result<(), GcpLoginFailure> {
        if initial.name() != current.name()
            || initial.gcp() != current.gcp()
            || initial.aws().is_some() != current.aws().is_some()
            || initial.ssh().is_some() != current.ssh().is_some()
        {
            return Err(GcpLoginFailure::ContextChanged);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcpLoginFailure {
    GcloudPlaneRequired,
    InvalidProfile,
    ContextChanged,
}

impl GcpLoginFailure {
    #[must_use]
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::GcloudPlaneRequired | Self::InvalidProfile => 2,
            Self::ContextChanged => 6,
        }
    }
}

impl fmt::Display for GcpLoginFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::GcloudPlaneRequired => {
                "refusing GCP login: the context does not declare a gcloud CLI credential plane"
            }
            Self::InvalidProfile => "refusing GCP login: the selected profile is invalid",
            Self::ContextChanged => {
                "refusing GCP login: authentication context changed after preview; retry the command"
            }
        })
    }
}

impl Error for GcpLoginFailure {}

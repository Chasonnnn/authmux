use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::{AuthenticationContext, DomainFailure};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    version: u32,
    contexts: BTreeMap<String, ContextConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextConfig {
    description: Option<String>,
    providers: ProviderConfigs,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderConfigs {
    aws: Option<AwsConfig>,
    ssh: Option<SshConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AwsConfig {
    profile: String,
    expected_account: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SshConfig {
    host_alias: String,
    expected_remote_principal: String,
    control_path: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectConfig {
    version: u32,
    project: ProjectBindingConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectBindingConfig {
    context: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectBinding {
    context_name: String,
    source: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextDefinition {
    name: String,
    aws: Option<AuthenticationContext>,
    ssh: Option<SshProviderDefinition>,
    description: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshProviderDefinition {
    host_alias: String,
    expected_remote_principal: String,
    control_path: Option<PathBuf>,
}

impl ContextDefinition {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn aws(&self) -> Option<&AuthenticationContext> {
        self.aws.as_ref()
    }

    #[must_use]
    pub fn ssh(&self) -> Option<&SshProviderDefinition> {
        self.ssh.as_ref()
    }

    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

impl SshProviderDefinition {
    #[must_use]
    pub fn host_alias(&self) -> &str {
        &self.host_alias
    }

    #[must_use]
    pub fn expected_remote_principal(&self) -> &str {
        &self.expected_remote_principal
    }

    #[must_use]
    pub fn control_path(&self) -> Option<&Path> {
        self.control_path.as_deref()
    }
}

impl ProjectBinding {
    /// Discovers the repository root and resolves its non-secret Project Binding.
    ///
    /// Discovery checks only `.authmux.toml` at the nearest repository root,
    /// identified by a `.git` file or directory. It never searches above that
    /// boundary.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure when no repository or binding exists, the
    /// file cannot be read, or the binding violates the restricted schema.
    pub fn discover(start: &Path) -> Result<Self, ConfigFailure> {
        let start = fs::canonicalize(start)
            .map_err(|error| ConfigFailure::io("could not resolve working directory", &error))?;
        let repository_root = repository_root(&start)?;
        let source = repository_root.join(".authmux.toml");
        match fs::symlink_metadata(&source) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => {
                return Err(ConfigFailure::new(
                    "project configuration must be a regular file",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(ConfigFailure::new(
                    "project binding is not configured at the repository root",
                ));
            }
            Err(error) => {
                return Err(ConfigFailure::io(
                    "could not inspect project configuration",
                    &error,
                ));
            }
        }
        let config_text = match fs::read_to_string(&source) {
            Ok(config) => config,
            Err(error) => {
                return Err(ConfigFailure::io(
                    "could not read project configuration",
                    &error,
                ));
            }
        };
        let config = toml::from_str::<ProjectConfig>(&config_text)
            .map_err(|_| ConfigFailure::new("project configuration is invalid"))?;
        if config.version != 1 {
            return Err(ConfigFailure::new(
                "unsupported project configuration version; expected version 1",
            ));
        }
        if looks_secret_shaped(&config.project.context) {
            return Err(ConfigFailure::new(
                "project configuration contains a secret-shaped context value",
            ));
        }
        if config.project.context.trim().is_empty() {
            return Err(ConfigFailure::new(
                "project configuration context cannot be empty",
            ));
        }
        if has_unsafe_display_characters(&config.project.context) {
            return Err(ConfigFailure::new(
                "project configuration context contains unsafe display characters",
            ));
        }

        Ok(Self {
            context_name: config.project.context,
            source,
        })
    }

    #[must_use]
    pub fn context_name(&self) -> &str {
        &self.context_name
    }

    #[must_use]
    pub fn source(&self) -> &Path {
        &self.source
    }
}

impl UserConfig {
    /// Parses and validates user-owned configuration.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure for malformed, unsupported, or
    /// secret-shaped configuration.
    pub fn parse(source: &str) -> Result<Self, ConfigFailure> {
        let config = toml::from_str::<Self>(source)
            .map_err(|_| ConfigFailure::new("user configuration is invalid"))?;
        if config.version != 1 {
            return Err(ConfigFailure::new(
                "unsupported user configuration version; expected version 1",
            ));
        }
        if config.contexts.keys().any(|name| looks_secret_shaped(name)) {
            return Err(ConfigFailure::new(
                "user configuration contains a secret-shaped context name",
            ));
        }
        if config
            .contexts
            .keys()
            .any(|name| has_unsafe_display_characters(name))
        {
            return Err(ConfigFailure::new(
                "user configuration contains an unsafe context name",
            ));
        }
        validate_provider_configs(&config)?;
        if config.contexts.values().any(|context| {
            context
                .description
                .as_deref()
                .is_some_and(looks_secret_shaped)
        }) {
            return Err(ConfigFailure::new(
                "user configuration contains a secret-shaped value where display metadata was expected",
            ));
        }
        if config.contexts.values().any(|context| {
            context
                .description
                .as_deref()
                .is_some_and(has_unsafe_display_characters)
        }) {
            return Err(ConfigFailure::new(
                "user configuration contains unsafe display metadata",
            ));
        }
        Ok(config)
    }

    /// Resolves one named Authentication Context.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure when the context is absent or invalid.
    pub fn resolve_context(
        &self,
        context_name: &str,
    ) -> Result<AuthenticationContext, ConfigFailure> {
        self.resolve_context_definition(context_name)
            .and_then(|definition| {
                definition.aws.ok_or_else(|| {
                    ConfigFailure::new(
                        "requested authentication context does not define AWS required by this command",
                    )
                })
            })
    }

    /// Resolves every configured Authentication Context in stable name order.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure when any configured context is invalid.
    pub fn context_definitions(&self) -> Result<Vec<ContextDefinition>, ConfigFailure> {
        self.contexts
            .keys()
            .map(|name| self.resolve_context_definition(name))
            .collect()
    }

    /// Resolves one named Authentication Context and its display metadata.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure when the context is absent or invalid.
    pub fn resolve_context_definition(
        &self,
        context_name: &str,
    ) -> Result<ContextDefinition, ConfigFailure> {
        let context = self
            .contexts
            .get(context_name)
            .ok_or_else(|| ConfigFailure::new("requested authentication context is not defined"))?;

        if context.providers.aws.is_none() && context.providers.ssh.is_none() {
            return Err(ConfigFailure::new(
                "authentication context must define at least one provider",
            ));
        }

        let aws = context
            .providers
            .aws
            .as_ref()
            .map(|aws| {
                AuthenticationContext::aws(context_name, &aws.profile, &aws.expected_account)
            })
            .transpose()
            .map_err(ConfigFailure::from)?;
        let ssh = context
            .providers
            .ssh
            .as_ref()
            .map(|ssh| SshProviderDefinition {
                host_alias: ssh.host_alias.clone(),
                expected_remote_principal: ssh.expected_remote_principal.clone(),
                control_path: ssh.control_path.clone(),
            });

        Ok(ContextDefinition {
            name: context_name.to_owned(),
            aws,
            ssh,
            description: context.description.clone(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigFailure {
    message: String,
}

impl ConfigFailure {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn io(action: &str, error: &std::io::Error) -> Self {
        Self::new(format!("{action} ({:?})", error.kind()))
    }
}

impl From<DomainFailure> for ConfigFailure {
    fn from(failure: DomainFailure) -> Self {
        Self::new(failure.to_string())
    }
}

impl fmt::Display for ConfigFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ConfigFailure {}

fn looks_secret_shaped(value: &str) -> bool {
    let aws_access_key = value.len() == 20
        && value.starts_with("AKIA")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit());
    let github_token = ["ghp_", "gho_", "ghu_", "ghs_", "github_pat_"]
        .iter()
        .any(|prefix| value.starts_with(prefix));
    let private_key = value.contains("-----BEGIN") && value.contains("PRIVATE KEY-----");
    let signed_url = value.contains("X-Amz-Signature=");
    let jwt = value.starts_with("eyJ") && value.matches('.').count() == 2;

    aws_access_key || github_token || private_key || signed_url || jwt
}

fn has_unsafe_display_characters(value: &str) -> bool {
    value.chars().count() > 512
        || value.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '\u{202a}'
                        ..='\u{202e}' | '\u{2066}'
                        ..='\u{2069}'
                )
        })
}

fn valid_ssh_host_alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn valid_ssh_control_path(path: &Path) -> bool {
    path.is_absolute()
        && !path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        && path
            .to_str()
            .is_some_and(|value| !has_unsafe_display_characters(value))
}

fn ssh_control_path_looks_secret_shaped(path: &Path) -> bool {
    path.components().any(|component| {
        let std::path::Component::Normal(value) = component else {
            return false;
        };
        value.to_str().is_some_and(looks_secret_shaped)
    })
}

fn validate_provider_configs(config: &UserConfig) -> Result<(), ConfigFailure> {
    if config.contexts.values().any(|context| {
        context
            .providers
            .aws
            .as_ref()
            .is_some_and(|aws| looks_secret_shaped(&aws.profile))
            || context.providers.ssh.as_ref().is_some_and(|ssh| {
                looks_secret_shaped(&ssh.host_alias)
                    || looks_secret_shaped(&ssh.expected_remote_principal)
            })
    }) {
        return Err(ConfigFailure::new(
            "user configuration contains a secret-shaped value where a provider profile was expected",
        ));
    }
    if config.contexts.values().any(|context| {
        context
            .providers
            .aws
            .as_ref()
            .is_some_and(|aws| has_unsafe_display_characters(&aws.profile))
            || context.providers.ssh.as_ref().is_some_and(|ssh| {
                has_unsafe_display_characters(&ssh.host_alias)
                    || has_unsafe_display_characters(&ssh.expected_remote_principal)
            })
    }) {
        return Err(ConfigFailure::new(
            "user configuration contains an unsafe provider profile",
        ));
    }
    if config.contexts.values().any(|context| {
        context
            .providers
            .ssh
            .as_ref()
            .and_then(|ssh| ssh.control_path.as_deref())
            .is_some_and(ssh_control_path_looks_secret_shaped)
    }) {
        return Err(ConfigFailure::new(
            "user configuration contains a secret-shaped SSH control path",
        ));
    }
    if config.contexts.values().any(|context| {
        context
            .providers
            .ssh
            .as_ref()
            .is_some_and(|ssh| !valid_ssh_host_alias(&ssh.host_alias))
    }) {
        return Err(ConfigFailure::new(
            "user configuration contains an invalid SSH host alias",
        ));
    }
    if config.contexts.values().any(|context| {
        context
            .providers
            .ssh
            .as_ref()
            .and_then(|ssh| ssh.control_path.as_deref())
            .is_some_and(|path| !valid_ssh_control_path(path))
    }) {
        return Err(ConfigFailure::new(
            "user configuration contains an invalid SSH control path",
        ));
    }
    if config.contexts.values().any(|context| {
        context.providers.ssh.as_ref().is_some_and(|ssh| {
            ssh.expected_remote_principal.trim().is_empty()
                || ssh.expected_remote_principal.trim() != ssh.expected_remote_principal
        })
    }) {
        return Err(ConfigFailure::new(
            "user configuration contains an invalid SSH Expected Identity",
        ));
    }
    if config
        .contexts
        .values()
        .any(|context| context.providers.aws.is_none() && context.providers.ssh.is_none())
    {
        return Err(ConfigFailure::new(
            "authentication context must define at least one provider",
        ));
    }
    Ok(())
}

fn repository_root(start: &Path) -> Result<PathBuf, ConfigFailure> {
    for candidate in start.ancestors() {
        match fs::symlink_metadata(candidate.join(".git")) {
            Ok(metadata) if metadata.is_dir() || metadata.is_file() => {
                return Ok(candidate.to_path_buf());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ConfigFailure::io(
                    "could not inspect repository boundary",
                    &error,
                ));
            }
        }
    }

    Err(ConfigFailure::new(
        "could not locate a repository root for project binding",
    ))
}

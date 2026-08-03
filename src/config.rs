use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

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
    aws: AwsConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AwsConfig {
    profile: String,
    expected_account: String,
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
        if config
            .contexts
            .values()
            .any(|context| looks_secret_shaped(&context.providers.aws.profile))
        {
            return Err(ConfigFailure::new(
                "user configuration contains a secret-shaped value where a provider profile was expected",
            ));
        }
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
        let context = self.contexts.get(context_name).ok_or_else(|| {
            ConfigFailure::new(format!(
                "authentication context `{context_name}` is not defined"
            ))
        })?;

        AuthenticationContext::aws(
            context_name,
            &context.providers.aws.profile,
            &context.providers.aws.expected_account,
        )
        .map_err(ConfigFailure::from)
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

use std::str;
use std::time::Duration;

use crate::{CommandSpec, ExecutionSelection, ProbePolicy, ProbeRunner, ProviderFailure};

pub struct SshClientReadinessCheck<R> {
    runner: R,
}

impl<R> SshClientReadinessCheck<R> {
    #[must_use]
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl<R> SshClientReadinessCheck<R>
where
    R: ProbeRunner,
{
    /// Observes only the installed OpenSSH client. It does not read SSH
    /// configuration, inspect an agent, or contact a remote host.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure when the bounded version probe cannot run
    /// or its output does not match the supported OpenSSH format.
    pub fn observe(&self) -> Result<SshClientReadiness, ProviderFailure> {
        let command = CommandSpec::new("ssh", ["-V"])?;
        let output = self.runner.probe(
            &command,
            &ExecutionSelection::none(),
            ProbePolicy::bounded(Duration::from_secs(2), 4_096),
        )?;
        if output.exit_code() != 0 || output.was_truncated() {
            return Err(ProviderFailure::sanitized(
                "OpenSSH client version could not be determined",
            ));
        }

        let version_output = if output.stdout().is_empty() {
            output.stderr()
        } else {
            output.stdout()
        };
        let version = parse_openssh_version(version_output).ok_or_else(|| {
            ProviderFailure::sanitized("OpenSSH version output was not recognized")
        })?;

        Ok(SshClientReadiness {
            client_version: version,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshClientReadiness {
    client_version: String,
}

impl SshClientReadiness {
    #[must_use]
    pub fn client_version(&self) -> &str {
        &self.client_version
    }

    #[must_use]
    pub const fn provider_contacted(&self) -> bool {
        false
    }
}

fn parse_openssh_version(bytes: &[u8]) -> Option<String> {
    let text = str::from_utf8(bytes).ok()?.trim();
    let version = text.split(',').next()?.trim();
    let numeric = version.strip_prefix("OpenSSH_")?;
    if version.len() > 32 || text == version && version.contains(char::is_whitespace) {
        return None;
    }

    let (major, minor_and_patch) = numeric.split_once('.')?;
    if major.is_empty() || !major.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let (minor, patch) = minor_and_patch
        .split_once('p')
        .map_or((minor_and_patch, None), |(minor, patch)| {
            (minor, Some(patch))
        });
    if minor.is_empty()
        || !minor.bytes().all(|byte| byte.is_ascii_digit())
        || patch.is_some_and(|patch| {
            patch.is_empty() || !patch.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return None;
    }

    Some(version.to_owned())
}

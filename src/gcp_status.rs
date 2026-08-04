use std::fs::{self, File};
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::str;

use crate::{
    EvidenceLevel, GcpProviderDefinition, IdentityMatch, ObservationReason, ObservedIdentity,
    ProviderFailure, ReauthenticationNeed, StatusObservation,
};

const CONFIG_LIMIT: u64 = 32 * 1024;

pub struct GcpLocalStatus {
    home: PathBuf,
}

impl GcpLocalStatus {
    #[must_use]
    pub fn new(home: impl Into<PathBuf>) -> Self {
        Self { home: home.into() }
    }

    /// Observes protected Google Cloud selection metadata without running
    /// gcloud, opening credential databases, or opening the ADC file.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure when a declared path escapes the user home.
    pub fn observe(
        &self,
        profile: &GcpProviderDefinition,
    ) -> Result<Vec<GcpPlaneObservation>, ProviderFailure> {
        let mut observations = Vec::new();
        if let Some(gcloud) = profile.gcloud() {
            if gcloud.config_dir() == self.home || !gcloud.config_dir().starts_with(&self.home) {
                return Err(ProviderFailure::sanitized(
                    "gcloud configuration path is outside the allowed user home",
                ));
            }
            let path = gcloud
                .config_dir()
                .join("configurations")
                .join(format!("config_{}", gcloud.configuration()));
            let selection = inspect_named_configuration(&path, &self.home);
            observations.push(gcloud_observation(gcloud, selection));
        }
        if let Some(adc) = profile.adc() {
            if adc.credential_file() == self.home || !adc.credential_file().starts_with(&self.home)
            {
                return Err(ProviderFailure::sanitized(
                    "ADC credential path is outside the allowed user home",
                ));
            }
            observations.push(adc_observation(inspect_adc_file(
                adc.credential_file(),
                &self.home,
            )));
        }
        Ok(observations)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcpCredentialPlane {
    GcloudCli,
    Adc,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcpProjectMatch {
    Match,
    Mismatch,
    Unverified,
    NotApplicable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpPlaneObservation {
    plane: GcpCredentialPlane,
    status: StatusObservation,
    observed_source_identity: Option<String>,
    source_identity_match: Option<IdentityMatch>,
    observed_project: Option<String>,
    project_match: GcpProjectMatch,
}

impl GcpPlaneObservation {
    #[must_use]
    pub fn plane(&self) -> GcpCredentialPlane {
        self.plane
    }

    #[must_use]
    pub fn status(&self) -> &StatusObservation {
        &self.status
    }

    #[must_use]
    pub fn observed_project(&self) -> Option<&str> {
        self.observed_project.as_deref()
    }

    #[must_use]
    pub fn observed_source_identity(&self) -> Option<&str> {
        self.observed_source_identity.as_deref()
    }

    #[must_use]
    pub fn source_identity_match(&self) -> Option<IdentityMatch> {
        self.source_identity_match
    }

    #[must_use]
    pub fn project_match(&self) -> GcpProjectMatch {
        self.project_match
    }

    #[must_use]
    pub const fn provider_contacted(&self) -> bool {
        false
    }
}

enum NamedConfigurationInspection {
    Parsed(NamedConfiguration),
    Missing,
    Invalid,
}

struct NamedConfiguration {
    account: Option<String>,
    project: Option<String>,
    impersonated_principal: Option<String>,
    unsupported_override: bool,
}

#[derive(Clone, Copy)]
enum AdcFileInspection {
    Ready,
    Missing,
    Invalid,
}

fn gcloud_observation(
    profile: &crate::GcloudProviderDefinition,
    inspection: NamedConfigurationInspection,
) -> GcpPlaneObservation {
    let (status, observed_project, observed_source_identity, source_identity_match) =
        match inspection {
            NamedConfigurationInspection::Parsed(configuration)
                if !configuration.unsupported_override
                    && !configuration
                        .impersonated_principal
                        .as_deref()
                        .is_some_and(|identity| identity.contains(','))
                    && (configuration.impersonated_principal.is_none()
                        || profile.expected_source_account().is_some()) =>
            {
                let observed_source_identity = profile
                    .expected_source_account()
                    .and(configuration.account.as_deref())
                    .map(str::to_owned);
                let source_identity_match = profile.expected_source_account().map(|expected| {
                    match configuration.account.as_deref() {
                        Some(observed) if observed == expected => IdentityMatch::Match,
                        Some(_) => IdentityMatch::Mismatch,
                        None => IdentityMatch::Unverified,
                    }
                });
                let selected_identity = configuration
                    .impersonated_principal
                    .or_else(|| configuration.account.clone());
                let status = selected_identity.map_or_else(
                    || {
                        StatusObservation::indeterminate_without_identity(
                            ObservationReason::Missing,
                            ReauthenticationNeed::Unknown,
                            EvidenceLevel::LocalMetadata,
                        )
                    },
                    |account| {
                        ObservedIdentity::provider_identity(account).map_or_else(
                            |_| {
                                StatusObservation::indeterminate_without_identity(
                                    ObservationReason::ProviderError,
                                    ReauthenticationNeed::Unknown,
                                    EvidenceLevel::LocalMetadata,
                                )
                            },
                            |identity| {
                                StatusObservation::indeterminate(
                                    identity,
                                    ObservationReason::InsufficientEvidence,
                                    ReauthenticationNeed::Unknown,
                                    EvidenceLevel::LocalMetadata,
                                )
                                .compare_to(profile.expected_principal())
                            },
                        )
                    },
                );
                (
                    status,
                    configuration.project,
                    observed_source_identity,
                    source_identity_match,
                )
            }
            NamedConfigurationInspection::Missing => (
                StatusObservation::indeterminate_without_identity(
                    ObservationReason::Missing,
                    ReauthenticationNeed::Unknown,
                    EvidenceLevel::LocalMetadata,
                ),
                None,
                None,
                None,
            ),
            NamedConfigurationInspection::Parsed(_) | NamedConfigurationInspection::Invalid => (
                StatusObservation::indeterminate_without_identity(
                    ObservationReason::ProviderError,
                    ReauthenticationNeed::Unknown,
                    EvidenceLevel::LocalMetadata,
                ),
                None,
                None,
                None,
            ),
        };
    let project_match = match (profile.expected_project(), observed_project.as_deref()) {
        (Some(expected), Some(observed)) if expected == observed => GcpProjectMatch::Match,
        (Some(_), Some(_)) => GcpProjectMatch::Mismatch,
        (Some(_), None) => GcpProjectMatch::Unverified,
        (None, _) => GcpProjectMatch::NotApplicable,
    };
    GcpPlaneObservation {
        plane: GcpCredentialPlane::GcloudCli,
        status,
        observed_source_identity,
        source_identity_match,
        observed_project,
        project_match,
    }
}

fn adc_observation(inspection: AdcFileInspection) -> GcpPlaneObservation {
    let reason = match inspection {
        AdcFileInspection::Ready => ObservationReason::InsufficientEvidence,
        AdcFileInspection::Missing => ObservationReason::Missing,
        AdcFileInspection::Invalid => ObservationReason::ProviderError,
    };
    GcpPlaneObservation {
        plane: GcpCredentialPlane::Adc,
        status: StatusObservation::indeterminate_without_identity(
            reason,
            ReauthenticationNeed::Unknown,
            EvidenceLevel::LocalMetadata,
        ),
        observed_source_identity: None,
        source_identity_match: None,
        observed_project: None,
        project_match: GcpProjectMatch::NotApplicable,
    }
}

fn inspect_adc_file(path: &Path, home: &Path) -> AdcFileInspection {
    let root = match fs::symlink_metadata(home) {
        Ok(metadata) if protected_directory(&metadata, None) => metadata,
        Ok(_) | Err(_) => return AdcFileInspection::Invalid,
    };
    let owner = root.uid();
    let Some(parent) = path.parent() else {
        return AdcFileInspection::Invalid;
    };
    let Ok(relative_parent) = parent.strip_prefix(home) else {
        return AdcFileInspection::Invalid;
    };
    let mut current = home.to_path_buf();
    for component in relative_parent.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if protected_directory(&metadata, Some(owner)) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return AdcFileInspection::Missing;
            }
            Ok(_) | Err(_) => return AdcFileInspection::Invalid,
        }
    }
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_file()
                && metadata.uid() == owner
                && metadata.mode().trailing_zeros() >= 6 =>
        {
            AdcFileInspection::Ready
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => AdcFileInspection::Missing,
        Ok(_) | Err(_) => AdcFileInspection::Invalid,
    }
}

fn inspect_named_configuration(path: &Path, home: &Path) -> NamedConfigurationInspection {
    let root = match fs::symlink_metadata(home) {
        Ok(metadata) if protected_directory(&metadata, None) => metadata,
        Ok(_) | Err(_) => return NamedConfigurationInspection::Invalid,
    };
    let owner = root.uid();
    let Some(parent) = path.parent() else {
        return NamedConfigurationInspection::Invalid;
    };
    let Ok(relative_parent) = parent.strip_prefix(home) else {
        return NamedConfigurationInspection::Invalid;
    };
    let mut current = home.to_path_buf();
    for component in relative_parent.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if protected_directory(&metadata, Some(owner)) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return NamedConfigurationInspection::Missing;
            }
            Ok(_) | Err(_) => return NamedConfigurationInspection::Invalid,
        }
    }
    let before = match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_file()
                && metadata.uid() == owner
                && metadata.mode() & 0o022 == 0
                && metadata.len() <= CONFIG_LIMIT =>
        {
            metadata
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return NamedConfigurationInspection::Missing;
        }
        Ok(_) | Err(_) => return NamedConfigurationInspection::Invalid,
    };
    let Ok(mut file) = File::open(path) else {
        return NamedConfigurationInspection::Invalid;
    };
    let Ok(after) = file.metadata() else {
        return NamedConfigurationInspection::Invalid;
    };
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.uid() != after.uid()
        || after.len() > CONFIG_LIMIT
    {
        return NamedConfigurationInspection::Invalid;
    }
    let mut bytes = Vec::new();
    if file
        .by_ref()
        .take(CONFIG_LIMIT + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > CONFIG_LIMIT
    {
        return NamedConfigurationInspection::Invalid;
    }
    parse_named_configuration(&bytes).map_or(
        NamedConfigurationInspection::Invalid,
        NamedConfigurationInspection::Parsed,
    )
}

fn protected_directory(metadata: &fs::Metadata, owner: Option<u32>) -> bool {
    metadata.is_dir()
        && owner.is_none_or(|owner| metadata.uid() == owner)
        && metadata.mode() & 0o022 == 0
}

fn parse_named_configuration(bytes: &[u8]) -> Option<NamedConfiguration> {
    let text = str::from_utf8(bytes).ok()?;
    let mut section = "";
    let mut account = None;
    let mut project = None;
    let mut impersonated_principal = None;
    let mut unsupported_override = false;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            section = name.trim();
            continue;
        }
        let (key, value) = line.split_once('=')?;
        let key = key.trim();
        let value = value.trim();
        if value.len() > 512 || value.chars().any(char::is_control) {
            return None;
        }
        match (section, key) {
            ("core", "account") => set_once(&mut account, value)?,
            ("core", "project") => set_once(&mut project, value)?,
            ("auth", "access_token_file" | "credential_file_override") if !value.is_empty() => {
                unsupported_override = true;
            }
            ("auth", "disable_credentials") if value.eq_ignore_ascii_case("true") => {
                unsupported_override = true;
            }
            ("auth", "impersonate_service_account") => {
                set_once(&mut impersonated_principal, value)?;
            }
            _ => {}
        }
    }
    Some(NamedConfiguration {
        account,
        project,
        impersonated_principal,
        unsupported_override,
    })
}

fn set_once(target: &mut Option<String>, value: &str) -> Option<()> {
    if target.is_some() || value.is_empty() || looks_secret_shaped(value) {
        return None;
    }
    *target = Some(value.to_owned());
    Some(())
}

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

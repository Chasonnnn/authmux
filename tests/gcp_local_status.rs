#![cfg(unix)]

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use authmux::{
    EvidenceLevel, GcpCredentialPlane, GcpLocalStatus, GcpProjectMatch, IdentityMatch,
    ObservationReason, ReauthenticationNeed, SessionUsability, UserConfig,
};

#[test]
fn protected_gcloud_selection_is_local_metadata_not_a_session_claim() {
    let fixture = GcpHomeFixture::new("gcloud-match");
    fixture.write_named_configuration(
        "crm-research",
        "[core]\naccount = researcher@example.test\nproject = fictional-project\n",
    );
    let profile = gcp_profile(&fixture, true, false);

    let observations = GcpLocalStatus::new(fixture.home())
        .observe(&profile)
        .expect("protected GCP metadata is observed");

    assert_eq!(observations.len(), 1);
    let observation = &observations[0];
    assert_eq!(observation.plane(), GcpCredentialPlane::GcloudCli);
    assert_eq!(
        observation
            .status()
            .observed_identity()
            .expect("local principal is observed")
            .value(),
        "researcher@example.test"
    );
    assert_eq!(observation.status().identity_match(), IdentityMatch::Match);
    assert_eq!(
        observation.status().usability(),
        SessionUsability::Indeterminate
    );
    assert_eq!(
        observation.status().reason(),
        Some(ObservationReason::InsufficientEvidence)
    );
    assert_eq!(
        observation.status().reauthentication_need(),
        ReauthenticationNeed::Unknown
    );
    assert_eq!(
        observation.status().evidence_level(),
        EvidenceLevel::LocalMetadata
    );
    assert_eq!(observation.project_match(), GcpProjectMatch::Match);
    assert_eq!(observation.observed_project(), Some("fictional-project"));
    assert!(!observation.provider_contacted());
}

#[test]
fn adc_file_metadata_never_becomes_an_identity_or_session_claim() {
    let fixture = GcpHomeFixture::new("adc-selection");
    fixture.write_adc_file("ghp_fictional_content_that_must_not_be_inspected");
    let profile = gcp_profile(&fixture, false, true);

    let observations = GcpLocalStatus::new(fixture.home())
        .observe(&profile)
        .expect("protected ADC path metadata is observed");

    assert_eq!(observations.len(), 1);
    let observation = &observations[0];
    assert_eq!(observation.plane(), GcpCredentialPlane::Adc);
    assert!(observation.status().observed_identity().is_none());
    assert_eq!(
        observation.status().identity_match(),
        IdentityMatch::Unverified
    );
    assert_eq!(
        observation.status().usability(),
        SessionUsability::Indeterminate
    );
    assert_eq!(
        observation.status().reason(),
        Some(ObservationReason::InsufficientEvidence)
    );
    assert_eq!(observation.project_match(), GcpProjectMatch::NotApplicable);
    assert!(!observation.provider_contacted());
}

#[test]
fn single_impersonation_compares_target_and_source_identities_independently() {
    let fixture = GcpHomeFixture::new("gcloud-impersonation");
    fixture.write_named_configuration(
        "crm-research",
        "[core]\n\
         account = researcher@example.test\n\
         project = fictional-project\n\
         [auth]\n\
         impersonate_service_account = workload@example.test\n",
    );
    let source = format!(
        "version = 1\n\
         [contexts.crm.providers.gcp.gcloud]\n\
         config_dir = \"{}\"\n\
         configuration = \"crm-research\"\n\
         expected_principal = \"workload@example.test\"\n\
         expected_source_account = \"researcher@example.test\"\n\
         expected_project = \"fictional-project\"\n",
        fixture.config_dir().display()
    );
    let profile = UserConfig::parse(&source)
        .expect("impersonated GCP selection is valid")
        .resolve_context_definition("crm")
        .expect("impersonated context resolves")
        .gcp()
        .expect("GCP Provider Profile exists")
        .clone();

    let observations = GcpLocalStatus::new(fixture.home())
        .observe(&profile)
        .expect("single impersonation is observed");

    let observation = &observations[0];
    assert_eq!(
        observation
            .status()
            .observed_identity()
            .expect("impersonated target is observed")
            .value(),
        "workload@example.test"
    );
    assert_eq!(observation.status().identity_match(), IdentityMatch::Match);
    assert_eq!(
        observation.observed_source_identity(),
        Some("researcher@example.test")
    );
    assert_eq!(
        observation.source_identity_match(),
        Some(IdentityMatch::Match)
    );
    assert_eq!(
        observation.status().usability(),
        SessionUsability::Indeterminate
    );
}

#[test]
fn secret_shaped_gcloud_metadata_becomes_sanitized_provider_error_data() {
    let fixture = GcpHomeFixture::new("gcloud-secret-output");
    let seeded_secret = "ghp_fictional_provider_output";
    fixture.write_named_configuration(
        "crm-research",
        &format!("[core]\naccount = {seeded_secret}\nproject = fictional-project\n"),
    );
    let profile = gcp_profile(&fixture, true, false);

    let observations = GcpLocalStatus::new(fixture.home())
        .observe(&profile)
        .expect("malformed native metadata remains status data");

    let observation = &observations[0];
    assert!(observation.status().observed_identity().is_none());
    assert!(observation.observed_project().is_none());
    assert_eq!(
        observation.status().reason(),
        Some(ObservationReason::ProviderError)
    );
    assert_eq!(
        observation.status().identity_match(),
        IdentityMatch::Unverified
    );
}

fn gcp_profile(
    fixture: &GcpHomeFixture,
    gcloud: bool,
    adc: bool,
) -> authmux::GcpProviderDefinition {
    let mut source = String::from("version = 1\n");
    if gcloud {
        write!(
            source,
            "[contexts.crm.providers.gcp.gcloud]\n\
             config_dir = \"{}\"\n\
             configuration = \"crm-research\"\n\
             expected_principal = \"researcher@example.test\"\n\
             expected_project = \"fictional-project\"\n",
            fixture.config_dir().display()
        )
        .expect("writing to a String cannot fail");
    }
    if adc {
        write!(
            source,
            "[contexts.crm.providers.gcp.adc]\n\
             mode = \"credential_file\"\n\
             credential_file = \"{}\"\n\
             expected_principal = \"workload@example.test\"\n",
            fixture.adc_file().display()
        )
        .expect("writing to a String cannot fail");
    }
    UserConfig::parse(&source)
        .expect("fixture GCP configuration is valid")
        .resolve_context_definition("crm")
        .expect("fixture context resolves")
        .gcp()
        .expect("fixture GCP Provider Profile exists")
        .clone()
}

struct GcpHomeFixture {
    path: PathBuf,
}

impl GcpHomeFixture {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "authmux-gcp-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("fixture root is created");
        set_mode(&path, 0o700);
        fs::create_dir_all(path.join("home/.config/gcloud/configurations"))
            .expect("gcloud configuration directory is created");
        for directory in [
            path.join("home"),
            path.join("home/.config"),
            path.join("home/.config/gcloud"),
            path.join("home/.config/gcloud/configurations"),
        ] {
            set_mode(&directory, 0o700);
        }
        Self { path }
    }

    fn home(&self) -> PathBuf {
        self.path.join("home")
    }

    fn config_dir(&self) -> PathBuf {
        self.path.join("home/.config/gcloud")
    }

    fn adc_file(&self) -> PathBuf {
        self.path.join("home/.config/gcloud/adc/crm.json")
    }

    fn write_named_configuration(&self, name: &str, contents: &str) {
        let path = self
            .config_dir()
            .join(format!("configurations/config_{name}"));
        fs::write(&path, contents).expect("fictional named configuration is written");
        set_mode(&path, 0o600);
    }

    fn write_adc_file(&self, contents: &str) {
        let path = self.adc_file();
        fs::create_dir_all(path.parent().expect("ADC fixture has a parent"))
            .expect("ADC directory is created");
        set_mode(path.parent().expect("ADC fixture has a parent"), 0o700);
        fs::write(&path, contents).expect("fictional ADC file is written");
        set_mode(&path, 0o600);
    }
}

impl Drop for GcpHomeFixture {
    fn drop(&mut self) {
        match fs::remove_dir_all(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("fixture cleanup failed: {error}"),
        }
    }
}

fn set_mode(path: &Path, mode: u32) {
    let mut permissions = fs::metadata(path)
        .expect("fixture metadata is readable")
        .permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions).expect("fixture permissions are set");
}

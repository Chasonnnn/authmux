use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use authmux::{ProjectBinding, UserConfig};

#[test]
fn github_provider_resolves_only_native_selector_and_expected_identity() {
    let source = "version = 1\n\
                  [contexts.github.providers.github]\n\
                  config_dir = \"/fictional/home/.config/gh/research\"\n\
                  hostname = \"github.com\"\n\
                  expected_login = \"fictional-researcher\"\n";

    let config = UserConfig::parse(source).expect("GitHub provider config is valid");
    let definition = config
        .resolve_context_definition("github")
        .expect("GitHub context resolves");
    let github = definition.github().expect("GitHub provider resolves");

    assert_eq!(
        github.config_dir().to_str(),
        Some("/fictional/home/.config/gh/research")
    );
    assert_eq!(github.hostname(), "github.com");
    assert_eq!(github.expected_login(), "fictional-researcher");
}

#[test]
fn github_provider_rejects_secret_shaped_metadata_without_echoing_it() {
    let seeded_secret = "ghp_fictional_provider_secret";
    let source = format!(
        "version = 1\n\
         [contexts.github.providers.github]\n\
         config_dir = \"/fictional/home/.config/gh/research\"\n\
         hostname = \"github.com\"\n\
         expected_login = \"{seeded_secret}\"\n"
    );

    let failure = UserConfig::parse(&source).expect_err("secret-shaped metadata is rejected");
    let diagnostic = failure.to_string();
    assert_eq!(
        diagnostic,
        "user configuration contains secret-shaped GitHub metadata"
    );
    assert!(!diagnostic.contains(seeded_secret));
}

#[test]
fn github_provider_rejects_unsafe_selector_metadata() {
    for source in [
        "version = 1\n\
         [contexts.github.providers.github]\n\
         config_dir = \"relative/gh\"\n\
         hostname = \"github.com\"\n\
         expected_login = \"fictional-researcher\"\n",
        "version = 1\n\
         [contexts.github.providers.github]\n\
         config_dir = \"/fictional/home/.config/gh/research\"\n\
         hostname = \"https://github.com\"\n\
         expected_login = \"fictional-researcher\"\n",
    ] {
        let failure = UserConfig::parse(source).expect_err("unsafe GitHub metadata is rejected");
        assert_eq!(
            failure.to_string(),
            "user configuration contains invalid GitHub Provider Profile metadata"
        );
    }
}

#[test]
fn secret_shaped_profile_value_is_rejected_without_echoing_it() {
    let seeded_secret = "AKIA1111111111111111";
    let source = format!(
        "version = 1\n\
         [contexts.crm.providers.aws]\n\
         profile = \"{seeded_secret}\"\n\
         expected_account = \"111111111111\"\n"
    );

    let failure = UserConfig::parse(&source).expect_err("secret-shaped values must be rejected");
    let diagnostic = failure.to_string();

    assert_eq!(
        diagnostic,
        "user configuration contains a secret-shaped value where a provider profile was expected"
    );
    assert!(!diagnostic.contains(seeded_secret));
}

#[test]
fn secret_shaped_user_context_name_is_rejected_without_echoing_it() {
    let seeded_secret = "ghp_fictional_context_value";
    let source = format!(
        "version = 1\n\
         [contexts.\"{seeded_secret}\".providers.aws]\n\
         profile = \"crm-development\"\n\
         expected_account = \"111111111111\"\n"
    );

    let failure = UserConfig::parse(&source).expect_err("secret-shaped names must be rejected");
    let diagnostic = failure.to_string();

    assert_eq!(
        diagnostic,
        "user configuration contains a secret-shaped context name"
    );
    assert!(!diagnostic.contains(seeded_secret));
}

#[test]
fn terminal_controls_in_display_metadata_are_rejected_without_echoing_them() {
    let seeded_control = "\u{1b}[31mfictional";
    let source = "version = 1\n\
                  [contexts.crm]\n\
                  description = \"\\u001b[31mfictional\"\n\
                  [contexts.crm.providers.aws]\n\
                  profile = \"crm-development\"\n\
                  expected_account = \"111111111111\"\n";

    let failure = UserConfig::parse(source).expect_err("terminal controls must be rejected");
    let diagnostic = failure.to_string();

    assert_eq!(
        diagnostic,
        "user configuration contains unsafe display metadata"
    );
    assert!(!diagnostic.contains(seeded_control));
}

#[test]
fn display_description_does_not_change_context_resolution() {
    let source = "version = 1\n\
                  [contexts.crm]\n\
                  description = \"Fictional CRM project\"\n\
                  [contexts.crm.providers.aws]\n\
                  profile = \"crm-development\"\n\
                  expected_account = \"111111111111\"\n";

    let config = UserConfig::parse(source).expect("documented display metadata is valid");
    let context = config
        .resolve_context("crm")
        .expect("fictional context resolves");

    assert_eq!(context.name(), "crm");
    assert_eq!(context.provider_profile(), "crm-development");
    assert_eq!(context.expected_account(), "111111111111");
}

#[test]
fn ssh_only_context_resolves_user_owned_intent_metadata() {
    let source = "version = 1\n\
                  [contexts.empire]\n\
                  description = \"Fictional Empire AI project\"\n\
                  [contexts.empire.providers.ssh]\n\
                  host_alias = \"empire-alpha\"\n\
                  expected_remote_principal = \"researcher@example.invalid\"\n\
                  control_path = \"/home/researcher/.ssh/controlmasters/empire-alpha.sock\"\n";

    let config = UserConfig::parse(source).expect("SSH intent metadata is valid");
    let definition = config
        .resolve_context_definition("empire")
        .expect("SSH-only context resolves for inspection");
    let ssh = definition.ssh().expect("SSH Provider Profile is available");

    assert_eq!(definition.name(), "empire");
    assert_eq!(
        definition.description(),
        Some("Fictional Empire AI project")
    );
    assert!(definition.aws().is_none());
    assert_eq!(ssh.host_alias(), "empire-alpha");
    assert_eq!(
        ssh.expected_remote_principal(),
        "researcher@example.invalid"
    );
    assert_eq!(
        ssh.control_path(),
        Some(Path::new(
            "/home/researcher/.ssh/controlmasters/empire-alpha.sock"
        ))
    );
}

#[test]
fn gcp_context_resolves_gcloud_and_adc_planes_independently() {
    let source = "version = 1\n\
                  [contexts.crm.providers.gcp.gcloud]\n\
                  config_dir = \"/home/researcher/.config/gcloud\"\n\
                  configuration = \"crm-research\"\n\
                  expected_principal = \"researcher@example.test\"\n\
                  expected_source_account = \"researcher@example.test\"\n\
                  expected_project = \"fictional-project\"\n\
                  [contexts.crm.providers.gcp.adc]\n\
                  mode = \"credential_file\"\n\
                  credential_file = \"/home/researcher/.config/gcloud/adc/crm.json\"\n\
                  expected_principal = \"workload@example.test\"\n";

    let config = UserConfig::parse(source).expect("GCP selection metadata is valid");
    let definition = config
        .resolve_context_definition("crm")
        .expect("GCP-only context resolves");
    let gcp = definition.gcp().expect("GCP Provider Profile is available");
    let gcloud = gcp.gcloud().expect("gcloud CLI plane is available");
    let adc = gcp.adc().expect("ADC plane is available");

    assert!(definition.aws().is_none());
    assert!(definition.ssh().is_none());
    assert_eq!(
        gcloud.config_dir(),
        Path::new("/home/researcher/.config/gcloud")
    );
    assert_eq!(gcloud.configuration(), "crm-research");
    assert_eq!(gcloud.expected_principal(), "researcher@example.test");
    assert_eq!(
        gcloud.expected_source_account(),
        Some("researcher@example.test")
    );
    assert_eq!(gcloud.expected_project(), Some("fictional-project"));
    assert_eq!(
        adc.credential_file(),
        Path::new("/home/researcher/.config/gcloud/adc/crm.json")
    );
    assert_eq!(adc.expected_principal(), "workload@example.test");
}

#[test]
fn gcp_context_requires_at_least_one_declared_credential_plane() {
    let source = "version = 1\n[contexts.crm.providers.gcp]\n";

    let failure = UserConfig::parse(source).expect_err("an empty GCP provider is invalid");

    assert_eq!(
        failure.to_string(),
        "GCP Provider Profile must define at least one credential plane"
    );
}

#[test]
fn relative_gcp_provider_paths_are_rejected_without_echoing_them() {
    let cases = [
        (
            "../fictional-sensitive/gcloud",
            "version = 1\n\
             [contexts.crm.providers.gcp.gcloud]\n\
             config_dir = \"../fictional-sensitive/gcloud\"\n\
             configuration = \"crm\"\n\
             expected_principal = \"researcher@example.test\"\n",
        ),
        (
            "../fictional-sensitive/adc.json",
            "version = 1\n\
             [contexts.crm.providers.gcp.adc]\n\
             mode = \"credential_file\"\n\
             credential_file = \"../fictional-sensitive/adc.json\"\n\
             expected_principal = \"workload@example.test\"\n",
        ),
    ];

    for (seeded_path, source) in cases {
        let failure = UserConfig::parse(source).expect_err("relative GCP paths are invalid");
        let diagnostic = failure.to_string();

        assert_eq!(
            diagnostic,
            "user configuration contains an invalid GCP provider path"
        );
        assert!(!diagnostic.contains(seeded_path));
    }
}

#[test]
fn invalid_gcloud_configuration_names_are_rejected_without_echoing_them() {
    for seeded_name in ["NONE", "9crm", "crm_research", "crm/escape"] {
        let source = format!(
            "version = 1\n\
             [contexts.crm.providers.gcp.gcloud]\n\
             config_dir = \"/home/researcher/.config/gcloud\"\n\
             configuration = \"{seeded_name}\"\n\
             expected_principal = \"researcher@example.test\"\n"
        );

        let failure =
            UserConfig::parse(&source).expect_err("unsafe configuration names are invalid");
        let diagnostic = failure.to_string();

        assert_eq!(
            diagnostic,
            "user configuration contains an invalid gcloud configuration name"
        );
        assert!(!diagnostic.contains(seeded_name));
    }
}

#[test]
fn secret_shaped_gcp_metadata_is_rejected_without_echoing_it() {
    let seeded_secret = "ghp_fictional_gcp_value";
    let sources = [
        format!(
            "version = 1\n\
             [contexts.crm.providers.gcp.gcloud]\n\
             config_dir = \"/home/researcher/.config/gcloud\"\n\
             configuration = \"crm\"\n\
             expected_principal = \"{seeded_secret}\"\n"
        ),
        format!(
            "version = 1\n\
             [contexts.crm.providers.gcp.adc]\n\
             mode = \"credential_file\"\n\
             credential_file = \"/home/researcher/.config/{seeded_secret}/adc.json\"\n\
             expected_principal = \"workload@example.test\"\n"
        ),
    ];

    for source in sources {
        let failure = UserConfig::parse(&source).expect_err("secret-shaped GCP data is invalid");
        let diagnostic = failure.to_string();

        assert_eq!(
            diagnostic,
            "user configuration contains secret-shaped GCP metadata"
        );
        assert!(!diagnostic.contains(seeded_secret));
    }
}

#[test]
fn blank_or_padded_gcp_expected_identities_are_rejected() {
    let sources = [
        "version = 1\n\
         [contexts.crm.providers.gcp.gcloud]\n\
         config_dir = \"/home/researcher/.config/gcloud\"\n\
         configuration = \"crm\"\n\
         expected_principal = \" researcher@example.test \"\n",
        "version = 1\n\
         [contexts.crm.providers.gcp.adc]\n\
         mode = \"credential_file\"\n\
         credential_file = \"/home/researcher/.config/gcloud/adc/crm.json\"\n\
         expected_principal = \"\"\n",
    ];

    for source in sources {
        let failure = UserConfig::parse(source).expect_err("invalid GCP identities are rejected");
        assert_eq!(
            failure.to_string(),
            "user configuration contains an invalid GCP Expected Identity"
        );
    }
}

#[test]
fn blank_or_padded_gcp_expected_project_is_rejected() {
    let source = "version = 1\n\
                  [contexts.crm.providers.gcp.gcloud]\n\
                  config_dir = \"/home/researcher/.config/gcloud\"\n\
                  configuration = \"crm\"\n\
                  expected_principal = \"researcher@example.test\"\n\
                  expected_project = \" fictional-project \"\n";

    let failure = UserConfig::parse(source).expect_err("invalid GCP projects are rejected");

    assert_eq!(
        failure.to_string(),
        "user configuration contains an invalid GCP expected project"
    );
}

#[test]
fn option_shaped_ssh_host_alias_is_rejected_without_echoing_it() {
    let seeded_alias = "-oProxyCommand=fictional-sensitive-command";
    let source = format!(
        "version = 1\n\
         [contexts.empire.providers.ssh]\n\
         host_alias = \"{seeded_alias}\"\n\
         expected_remote_principal = \"researcher@example.invalid\"\n"
    );

    let failure = UserConfig::parse(&source).expect_err("unsafe SSH aliases must be rejected");
    let diagnostic = failure.to_string();

    assert_eq!(
        diagnostic,
        "user configuration contains an invalid SSH host alias"
    );
    assert!(!diagnostic.contains(seeded_alias));
}

#[test]
fn secret_shaped_ssh_expected_identity_is_rejected_without_echoing_it() {
    let seeded_secret = "ghp_fictional_remote_principal";
    let source = format!(
        "version = 1\n\
         [contexts.empire.providers.ssh]\n\
         host_alias = \"empire-alpha\"\n\
         expected_remote_principal = \"{seeded_secret}\"\n"
    );

    let failure =
        UserConfig::parse(&source).expect_err("secret-shaped SSH identity must be rejected");
    let diagnostic = failure.to_string();

    assert_eq!(
        diagnostic,
        "user configuration contains a secret-shaped value where a provider profile was expected"
    );
    assert!(!diagnostic.contains(seeded_secret));
}

#[test]
fn relative_ssh_control_path_is_rejected_without_echoing_it() {
    let seeded_path = "../fictional-sensitive/control.sock";
    let source = format!(
        "version = 1\n\
         [contexts.empire.providers.ssh]\n\
         host_alias = \"empire-alpha\"\n\
         expected_remote_principal = \"researcher@example.invalid\"\n\
         control_path = \"{seeded_path}\"\n"
    );

    let failure =
        UserConfig::parse(&source).expect_err("relative SSH control paths must be rejected");
    let diagnostic = failure.to_string();

    assert_eq!(
        diagnostic,
        "user configuration contains an invalid SSH control path"
    );
    assert!(!diagnostic.contains(seeded_path));
}

#[test]
fn secret_shaped_ssh_control_path_is_rejected_without_echoing_it() {
    let seeded_secret = "ghp_fictional_control_socket";
    let source = format!(
        "version = 1\n\
         [contexts.empire.providers.ssh]\n\
         host_alias = \"empire-alpha\"\n\
         expected_remote_principal = \"researcher@example.invalid\"\n\
         control_path = \"/home/researcher/.ssh/{seeded_secret}\"\n"
    );

    let failure =
        UserConfig::parse(&source).expect_err("secret-shaped control paths must be rejected");
    let diagnostic = failure.to_string();

    assert_eq!(
        diagnostic,
        "user configuration contains a secret-shaped SSH control path"
    );
    assert!(!diagnostic.contains(seeded_secret));
}

#[test]
fn project_binding_reports_repository_root_provenance() {
    let fixture = FixtureDirectory::new("binding-provenance");
    fs::create_dir_all(fixture.path.join(".git")).expect("repository marker is created");
    fs::write(
        fixture.path.join(".authmux.toml"),
        "version = 1\n[project]\ncontext = \"crm\"\n",
    )
    .expect("project binding is written");
    let nested = fixture.path.join("nested");
    fs::create_dir(&nested).expect("nested directory is created");

    let binding = ProjectBinding::discover(&nested).expect("binding resolves");
    let expected_source = fs::canonicalize(&fixture.path)
        .expect("fixture root canonicalizes")
        .join(".authmux.toml");

    assert_eq!(binding.context_name(), "crm");
    assert_eq!(binding.source(), expected_source);
}

#[test]
fn project_binding_rejects_provider_overrides() {
    let fixture = FixtureDirectory::new("binding-provider-override");
    fs::create_dir_all(fixture.path.join(".git")).expect("repository marker is created");
    fs::write(
        fixture.path.join(".authmux.toml"),
        "version = 1\n\
         [project]\n\
         context = \"crm\"\n\
         profile = \"unexpected-override\"\n",
    )
    .expect("invalid project binding is written");

    let failure = ProjectBinding::discover(&fixture.path)
        .expect_err("repository config must not override provider selection");

    assert_eq!(failure.to_string(), "project configuration is invalid");
}

#[test]
fn secret_shaped_project_context_is_rejected_without_echoing_it() {
    let fixture = FixtureDirectory::new("binding-secret");
    let seeded_secret = "ghp_fictional_token_value";
    fs::create_dir_all(fixture.path.join(".git")).expect("repository marker is created");
    fs::write(
        fixture.path.join(".authmux.toml"),
        format!("version = 1\n[project]\ncontext = \"{seeded_secret}\"\n"),
    )
    .expect("secret-shaped binding is written");

    let failure = ProjectBinding::discover(&fixture.path)
        .expect_err("secret-shaped project context must be rejected");
    let diagnostic = failure.to_string();

    assert_eq!(
        diagnostic,
        "project configuration contains a secret-shaped context value"
    );
    assert!(!diagnostic.contains(seeded_secret));
}

#[cfg(unix)]
#[test]
fn symlinked_project_binding_is_rejected() {
    use std::os::unix::fs::symlink;

    let fixture = FixtureDirectory::new("binding-symlink");
    fs::create_dir_all(fixture.path.join(".git")).expect("repository marker is created");
    let external = fixture.path.join("external-binding.toml");
    fs::write(&external, "version = 1\n[project]\ncontext = \"crm\"\n")
        .expect("external binding is written");
    symlink(&external, fixture.path.join(".authmux.toml"))
        .expect("project binding symlink is created");

    let failure = ProjectBinding::discover(&fixture.path)
        .expect_err("a repository binding must be a regular file");

    assert_eq!(
        failure.to_string(),
        "project configuration must be a regular file"
    );
}

#[test]
fn terminal_controls_in_project_context_are_rejected() {
    let fixture = FixtureDirectory::new("binding-terminal-control");
    fs::create_dir_all(fixture.path.join(".git")).expect("repository marker is created");
    fs::write(
        fixture.path.join(".authmux.toml"),
        "version = 1\n[project]\ncontext = \"\\u001b[31mcrm\"\n",
    )
    .expect("unsafe binding is written");

    let failure = ProjectBinding::discover(&fixture.path)
        .expect_err("terminal controls in a binding must be rejected");

    assert_eq!(
        failure.to_string(),
        "project configuration context contains unsafe display characters"
    );
}

struct FixtureDirectory {
    path: PathBuf,
}

impl FixtureDirectory {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after the Unix epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("authmux-{label}-{}-{unique}", std::process::id()));
        fs::create_dir(&path).expect("fixture directory is created");
        Self { path }
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        remove_fixture(&self.path);
    }
}

fn remove_fixture(path: &Path) {
    match fs::remove_dir_all(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("fixture cleanup failed: {error}"),
    }
}

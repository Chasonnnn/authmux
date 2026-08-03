use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use authmux::{ProjectBinding, UserConfig};

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

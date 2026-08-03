#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn context_show_reports_an_explicit_context_without_observing_the_provider() {
    let fixture = FixtureDirectory::new("context-show-\u{1b}[31mexplicit");
    let (bin_directory, provider_marker) = fixture.configure();
    let config_source = fs::canonicalize(&fixture.path)
        .expect("fixture path canonicalizes")
        .join("config")
        .join("authmux")
        .join("config.toml");

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["context", "show", "--context", "crm"])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("report is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(
        stdout,
        format!(
            "context: crm\n\
             selection: command line\n\
             description: Fictional CRM project\n\
             definition source: {}\n\
             aws profile: crm-development\n\
             expected AWS account: 111111111111\n\
             provider state: not observed\n",
            escaped_path(&config_source)
        )
    );
    assert!(stderr.is_empty());
    assert!(
        !stdout.contains('\u{1b}'),
        "control characters must be escaped"
    );
    assert!(!provider_marker.exists(), "context show must not run AWS");
}

#[test]
fn context_show_reports_project_binding_provenance_from_a_nested_directory() {
    let fixture = FixtureDirectory::new("context-show-binding");
    let (bin_directory, provider_marker) = fixture.configure();
    let nested = fixture.path.join("nested");
    fs::create_dir_all(fixture.path.join(".git")).expect("repository marker is created");
    fs::create_dir(&nested).expect("nested directory is created");
    let binding_source = fixture.path.join(".authmux.toml");
    fs::write(
        &binding_source,
        "version = 1\n[project]\ncontext = \"crm\"\n",
    )
    .expect("project binding is written");
    let canonical_root = fs::canonicalize(&fixture.path).expect("fixture path canonicalizes");
    let canonical_binding = canonical_root.join(".authmux.toml");
    let canonical_config = canonical_root
        .join("config")
        .join("authmux")
        .join("config.toml");

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["context", "show"])
        .current_dir(nested)
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("report is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(
        stdout,
        format!(
            "context: crm\n\
             selection: project binding\n\
             binding source: {}\n\
             description: Fictional CRM project\n\
             definition source: {}\n\
             aws profile: crm-development\n\
             expected AWS account: 111111111111\n\
             provider state: not observed\n",
            canonical_binding.display(),
            canonical_config.display()
        )
    );
    assert!(stderr.is_empty());
    assert!(!provider_marker.exists(), "context show must not run AWS");
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

    fn configure(&self) -> (PathBuf, PathBuf) {
        let bin_directory = self.path.join("bin");
        let config_directory = self.path.join("config").join("authmux");
        fs::create_dir_all(&bin_directory).expect("fixture bin directory is created");
        fs::create_dir_all(&config_directory).expect("fixture config directory is created");

        let provider_marker = self.path.join("provider-ran");
        let aws = bin_directory.join("aws");
        fs::write(
            &aws,
            format!(
                "#!/bin/sh\ntouch '{}'\nexit 97\n",
                provider_marker.display()
            ),
        )
        .expect("fictional aws fixture is written");
        let mut permissions = fs::metadata(&aws)
            .expect("fixture metadata is readable")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&aws, permissions).expect("fictional aws fixture is executable");

        fs::write(
            config_directory.join("config.toml"),
            "version = 1\n\
             [contexts.crm]\n\
             description = \"Fictional CRM project\"\n\
             [contexts.crm.providers.aws]\n\
             profile = \"crm-development\"\n\
             expected_account = \"111111111111\"\n",
        )
        .expect("fictional user config is written");

        (bin_directory, provider_marker)
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

fn escaped_path(path: &Path) -> String {
    path.to_string_lossy().replace('\u{1b}', "\\u{1b}")
}

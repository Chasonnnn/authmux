#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn context_list_matches_the_terminal_golden_without_observing_providers() {
    let fixture = FixtureDirectory::new("context-list-human");
    let (bin_directory, provider_marker) = fixture.configure();

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["context", "list"])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("report is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(
        stdout,
        include_str!("fixtures/golden/context-list-human.txt")
    );
    assert!(stderr.is_empty());
    assert!(!provider_marker.exists(), "context list must not run AWS");
}

#[test]
fn context_list_json_matches_the_versioned_golden() {
    let fixture = FixtureDirectory::new("context-list-json");
    let (bin_directory, provider_marker) = fixture.configure();

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["context", "list", "--json"])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("report is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(
        stdout,
        include_str!("fixtures/golden/context-list-json.json")
    );
    assert!(stderr.is_empty());
    assert!(!provider_marker.exists(), "context list must not run AWS");
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
             expected_account = \"111111111111\"\n\
             [contexts.analytics.providers.aws]\n\
             profile = \"analytics-readonly\"\n\
             expected_account = \"222222222222\"\n",
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

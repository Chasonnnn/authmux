#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn status_reports_matching_local_metadata_without_calling_sts() {
    let fixture = FixtureDirectory::new("status-match");
    let (bin_directory, sts_marker) = fixture.configure(Some("111111111111"));

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["status", "--context", "crm"])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("report is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(stdout.contains("context: crm\n"));
    assert!(stdout.contains("provider: aws\n"));
    assert!(stdout.contains("profile: crm-development\n"));
    assert!(stdout.contains("expected identity: 111111111111\n"));
    assert!(stdout.contains("observed identity: 111111111111\n"));
    assert!(stdout.contains("identity match: match\n"));
    assert!(stdout.contains("session usability: indeterminate\n"));
    assert!(stdout.contains("reason: insufficient_evidence\n"));
    assert!(stdout.contains("reauthentication need: unknown\n"));
    assert!(stdout.contains("evidence level: local_metadata\n"));
    assert!(stdout.contains("provider contacted: no\n"));
    assert!(stdout.contains("observed at unix: "));
    assert!(stderr.is_empty());
    assert!(!sts_marker.exists(), "read-only status must not call STS");
}

#[test]
fn absent_local_metadata_is_reported_as_unverified_data() {
    let fixture = FixtureDirectory::new("status-absent");
    let (bin_directory, sts_marker) = fixture.configure(None);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["status", "--context", "crm"])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("report is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(stdout.contains("observed identity: not observed\n"));
    assert!(stdout.contains("identity match: unverified\n"));
    assert!(stdout.contains("session usability: indeterminate\n"));
    assert!(stderr.is_empty());
    assert!(!sts_marker.exists(), "read-only status must not call STS");
}

#[test]
fn malformed_local_metadata_is_not_exposed_by_the_cli() {
    const SENSITIVE_FIXTURE: &str = "111111111111 unexpected-sensitive-metadata";
    let fixture = FixtureDirectory::new("status-malformed");
    let (bin_directory, sts_marker) = fixture.configure(Some(SENSITIVE_FIXTURE));

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["status", "--context", "crm"])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("report is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(stdout.contains("observed identity: not observed\n"));
    assert!(stdout.contains("identity match: unverified\n"));
    assert!(stdout.contains("reason: provider_error\n"));
    assert!(!stdout.contains(SENSITIVE_FIXTURE));
    assert!(!stderr.contains(SENSITIVE_FIXTURE));
    assert!(!sts_marker.exists(), "read-only status must not call STS");
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

    fn configure(&self, account: Option<&str>) -> (PathBuf, PathBuf) {
        let bin_directory = self.path.join("bin");
        let config_directory = self.path.join("config").join("authmux");
        fs::create_dir_all(&bin_directory).expect("fixture bin directory is created");
        fs::create_dir_all(&config_directory).expect("fixture config directory is created");

        let sts_marker = self.path.join("sts-ran");
        let result = account.map_or_else(
            || "exit 1".to_owned(),
            |account| format!("printf '{account}\\n'; exit 0"),
        );
        let aws = bin_directory.join("aws");
        fs::write(
            &aws,
            format!(
                "#!/bin/sh\n\
                 if [ \"$1\" = \"sts\" ]; then touch '{}'; exit 97; fi\n\
                 if [ \"$1 $2 $3 $4 $5\" = \"configure get sso_account_id --profile crm-development\" ]; then {result}; fi\n\
                 exit 64\n",
                sts_marker.display()
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
             [contexts.crm.providers.aws]\n\
             profile = \"crm-development\"\n\
             expected_account = \"111111111111\"\n",
        )
        .expect("fictional user config is written");

        (bin_directory, sts_marker)
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

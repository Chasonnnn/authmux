#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn doctor_matches_the_terminal_golden_without_contacting_aws() {
    let fixture = FixtureDirectory::new("doctor-pass");
    let (bin_directory, sts_marker) = fixture.configure("111111111111");

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["doctor", "--context", "crm"])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("report is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(stdout, include_str!("fixtures/golden/doctor-human.txt"));
    assert!(stderr.is_empty());
    assert!(!sts_marker.exists(), "doctor must not call STS");
}

#[test]
fn doctor_json_matches_the_versioned_golden() {
    let fixture = FixtureDirectory::new("doctor-json");
    let (bin_directory, sts_marker) = fixture.configure("111111111111");

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["doctor", "--json", "--context", "crm"])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("report is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(stdout, include_str!("fixtures/golden/doctor-json.json"));
    assert!(stderr.is_empty());
    assert!(!sts_marker.exists(), "doctor must not call STS");
}

#[test]
fn doctor_fails_on_a_local_profile_identity_mismatch() {
    let fixture = FixtureDirectory::new("doctor-mismatch");
    let (bin_directory, sts_marker) = fixture.configure("222222222222");

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["doctor", "--context", "crm", "--json"])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("report is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(stdout.contains("\"result\": \"fail\""));
    assert!(stdout.contains("\"outcome\": \"fail\""));
    assert!(stdout.contains("configured account does not match expected identity"));
    assert!(stderr.is_empty());
    assert!(!sts_marker.exists(), "doctor must not call STS");
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

    fn configure(&self, account: &str) -> (PathBuf, PathBuf) {
        let bin_directory = self.path.join("bin");
        let config_directory = self.path.join("config").join("authmux");
        fs::create_dir_all(&bin_directory).expect("fixture bin directory is created");
        fs::create_dir_all(&config_directory).expect("fixture config directory is created");

        let sts_marker = self.path.join("sts-ran");
        let aws = bin_directory.join("aws");
        fs::write(
            &aws,
            format!(
                "#!/bin/sh\n\
                 if [ \"$1\" = \"sts\" ]; then touch '{}'; exit 97; fi\n\
                 if [ \"$1\" = \"--version\" ]; then printf 'aws-cli/2.36.11 Python/3.14.6 fictional/1.0\\n'; exit 0; fi\n\
                 if [ \"$1 $2 $3 $4 $5\" = \"configure get sso_account_id --profile crm-development\" ]; then printf '{account}\\n'; exit 0; fi\n\
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

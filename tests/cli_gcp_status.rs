#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn gcp_status_renders_independent_gcloud_and_adc_observations_without_paths() {
    let fixture = GcpCliFixture::new("status");

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["status", "--context", "crm", "--provider", "gcp"])
        .env("HOME", fixture.home())
        .env("XDG_CONFIG_HOME", fixture.authmux_config_root())
        .env("PATH", "/usr/bin:/bin")
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("report is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(
        normalize_observation_times(&stdout),
        "context: crm\n\
         provider: gcp\n\
         credential plane: gcloud_cli\n\
         profile: crm-research\n\
         expected identity: researcher@example.test\n\
         observed identity: researcher@example.test\n\
         identity match: match\n\
         expected project: fictional-project\n\
         observed project: fictional-project\n\
         project match: match\n\
         session usability: indeterminate\n\
         reason: insufficient_evidence\n\
         reauthentication need: unknown\n\
         evidence level: local_metadata\n\
         provider contacted: no\n\
         observed at unix: <observed_at_unix>\n\
         \n\
         provider: gcp\n\
         credential plane: adc\n\
         profile: credential_file\n\
         expected identity: workload@example.test\n\
         observed identity: not observed\n\
         identity match: unverified\n\
         session usability: indeterminate\n\
         reason: insufficient_evidence\n\
         reauthentication need: unknown\n\
         evidence level: local_metadata\n\
         provider contacted: no\n\
         observed at unix: <observed_at_unix>\n"
    );
    assert!(stderr.is_empty());
    assert!(!stdout.contains(&fixture.gcloud_dir().display().to_string()));
    assert!(!stdout.contains(&fixture.adc_file().display().to_string()));
}

#[test]
fn gcp_status_json_uses_schema_v3_and_keeps_planes_separate() {
    let fixture = GcpCliFixture::new("status-json");

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["status", "--context", "crm", "--provider", "gcp", "--json"])
        .env("HOME", fixture.home())
        .env("XDG_CONFIG_HOME", fixture.authmux_config_root())
        .env("PATH", "/usr/bin:/bin")
        .output()
        .expect("authmux runs");

    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("status is valid JSON");

    assert_eq!(document["schema_version"], 3);
    assert_eq!(document["observations"].as_array().map(Vec::len), Some(2));
    assert_eq!(
        document["observations"][0]["credential_plane"],
        "gcloud_cli"
    );
    assert_eq!(document["observations"][1]["credential_plane"], "adc");
    assert_eq!(document["observations"][1]["identity_match"], "unverified");
    assert_eq!(
        document["observations"][1]["session_usability"],
        "indeterminate"
    );
    let stdout = String::from_utf8(output.stdout).expect("report is UTF-8");
    assert!(!stdout.contains(&fixture.gcloud_dir().display().to_string()));
    assert!(!stdout.contains(&fixture.adc_file().display().to_string()));
}

#[test]
fn gcp_doctor_checks_local_readiness_without_executing_gcloud() {
    let fixture = GcpCliFixture::new("doctor");
    let (bin_directory, execution_marker) = fixture.configure_gcloud_executable();

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["doctor", "--context", "crm", "--provider", "gcp"])
        .env("HOME", fixture.home())
        .env("XDG_CONFIG_HOME", fixture.authmux_config_root())
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("report is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(stdout.contains("- [pass] gcloud_executable: gcloud executable is available\n"));
    assert!(stdout.contains("- [pass] gcloud_identity: local gcloud identity matches\n"));
    assert!(stdout.contains("- [pass] gcloud_project: local gcloud project matches\n"));
    assert!(stdout.contains("- [pass] adc_selector: ADC credential-file selector is available\n"));
    assert!(stdout.contains(
        "- [warning] gcp_session: credential usability, refresh, authorization, and expiry were not observed\n"
    ));
    assert!(stdout.contains("provider contacted: no\n"));
    assert!(stderr.is_empty());
    assert!(!execution_marker.exists(), "doctor must not execute gcloud");
}

#[test]
fn context_show_reports_gcp_intent_without_exposing_provider_paths() {
    let fixture = GcpCliFixture::new("context-show");

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["context", "show", "--context", "crm"])
        .env("HOME", fixture.home())
        .env("XDG_CONFIG_HOME", fixture.authmux_config_root())
        .env("PATH", "/usr/bin:/bin")
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("report is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(stdout.contains("gcloud configuration: crm-research\n"));
    assert!(stdout.contains("expected gcloud identity: researcher@example.test\n"));
    assert!(stdout.contains("expected gcloud project: fictional-project\n"));
    assert!(stdout.contains("ADC mode: credential_file\n"));
    assert!(stdout.contains("expected ADC identity: workload@example.test\n"));
    assert!(!stdout.contains(&fixture.gcloud_dir().display().to_string()));
    assert!(!stdout.contains(&fixture.adc_file().display().to_string()));
    assert!(stderr.is_empty());
}

#[test]
fn context_list_json_identifies_each_gcp_credential_plane() {
    let fixture = GcpCliFixture::new("context-list");

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["context", "list", "--json"])
        .env("HOME", fixture.home())
        .env("XDG_CONFIG_HOME", fixture.authmux_config_root())
        .env("PATH", "/usr/bin:/bin")
        .output()
        .expect("authmux runs");

    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("context list is valid JSON");

    assert_eq!(document["schema_version"], 2);
    assert_eq!(
        document["contexts"][0]["providers"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    assert_eq!(
        document["contexts"][0]["providers"][0]["credential_plane"],
        "gcloud_cli"
    );
    assert_eq!(
        document["contexts"][0]["providers"][1]["credential_plane"],
        "adc"
    );
}

struct GcpCliFixture {
    path: PathBuf,
}

impl GcpCliFixture {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "authmux-cli-gcp-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("fixture root is created");
        set_mode(&path, 0o700);
        let fixture = Self { path };
        fixture.configure();
        fixture
    }

    fn home(&self) -> PathBuf {
        self.path.join("home")
    }

    fn authmux_config_root(&self) -> PathBuf {
        self.path.join("authmux-config")
    }

    fn gcloud_dir(&self) -> PathBuf {
        self.home().join(".config/gcloud")
    }

    fn adc_file(&self) -> PathBuf {
        self.gcloud_dir().join("adc/crm.json")
    }

    fn configure(&self) {
        for directory in [
            self.home(),
            self.home().join(".config"),
            self.gcloud_dir(),
            self.gcloud_dir().join("configurations"),
            self.gcloud_dir().join("adc"),
            self.authmux_config_root(),
            self.authmux_config_root().join("authmux"),
        ] {
            fs::create_dir_all(&directory).expect("fixture directory is created");
            set_mode(&directory, 0o700);
        }
        let named = self.gcloud_dir().join("configurations/config_crm-research");
        fs::write(
            &named,
            "[core]\naccount = researcher@example.test\nproject = fictional-project\n",
        )
        .expect("fictional named configuration is written");
        set_mode(&named, 0o600);
        fs::write(self.adc_file(), "fictional contents are never opened")
            .expect("fictional ADC file is written");
        set_mode(&self.adc_file(), 0o600);
        fs::write(
            self.authmux_config_root().join("authmux/config.toml"),
            format!(
                "version = 1\n\
                 [contexts.crm.providers.gcp.gcloud]\n\
                 config_dir = \"{}\"\n\
                 configuration = \"crm-research\"\n\
                 expected_principal = \"researcher@example.test\"\n\
                 expected_project = \"fictional-project\"\n\
                 [contexts.crm.providers.gcp.adc]\n\
                 mode = \"credential_file\"\n\
                 credential_file = \"{}\"\n\
                 expected_principal = \"workload@example.test\"\n",
                self.gcloud_dir().display(),
                self.adc_file().display()
            ),
        )
        .expect("authmux user configuration is written");
    }

    fn configure_gcloud_executable(&self) -> (PathBuf, PathBuf) {
        let bin_directory = self.path.join("bin");
        fs::create_dir(&bin_directory).expect("fixture bin directory is created");
        set_mode(&bin_directory, 0o700);
        let execution_marker = self.path.join("gcloud-executed");
        let executable = bin_directory.join("gcloud");
        fs::write(
            &executable,
            format!(
                "#!/bin/sh\ntouch '{}'\nexit 97\n",
                execution_marker.display()
            ),
        )
        .expect("fictional gcloud executable is written");
        set_mode(&executable, 0o700);
        (bin_directory, execution_marker)
    }
}

impl Drop for GcpCliFixture {
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

fn normalize_observation_times(report: &str) -> String {
    report
        .lines()
        .map(|line| {
            if line.starts_with("observed at unix: ") {
                "observed at unix: <observed_at_unix>"
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

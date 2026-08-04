#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
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
    assert_eq!(
        normalize_human_observation_time(&stdout),
        include_str!("fixtures/golden/status-human.txt")
    );
    assert!(stderr.is_empty());
    assert!(!sts_marker.exists(), "read-only status must not call STS");
}

#[test]
fn json_status_matches_the_versioned_schema_golden() {
    let fixture = FixtureDirectory::new("status-json");
    let (bin_directory, sts_marker) = fixture.configure(Some("111111111111"));

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["status", "--context", "crm", "--json"])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("report is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(
        normalize_json_observation_time(&stdout),
        include_str!("fixtures/golden/status-json.json")
    );
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
fn aws_login_session_reports_only_its_account_identity() {
    const LOGIN_SESSION: &str =
        "arn:aws:sts::111111111111:assumed-role/FictionalRole/sensitive-principal";
    let fixture = FixtureDirectory::new("status-login-session");
    let (bin_directory, sts_marker) = fixture.configure_login_session(LOGIN_SESSION);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["status", "--context", "crm"])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("report is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(stdout.contains("observed identity: 111111111111\n"));
    assert!(stdout.contains("identity match: match\n"));
    assert!(!stdout.contains(LOGIN_SESSION));
    assert!(!stderr.contains(LOGIN_SESSION));
    assert!(!sts_marker.exists(), "read-only status must not call STS");
}

#[test]
fn ssh_status_reports_active_transport_without_identity_or_session_claims() {
    let fixture = FixtureDirectory::new("status-ssh-active");
    let ssh_home = SshHomeFixture::new("active");
    let control_path = ssh_home.control_path();
    let _listener = UnixListener::bind(&control_path).expect("fixture control socket is created");
    let mut socket_permissions = fs::metadata(&control_path)
        .expect("control socket metadata is readable")
        .permissions();
    socket_permissions.set_mode(0o600);
    fs::set_permissions(&control_path, socket_permissions)
        .expect("control socket permissions are set");
    let bin_directory = ssh_home.configure_ssh(0);
    let config_directory = fixture.path.join("config").join("authmux");
    fs::create_dir_all(&config_directory).expect("config directory is created");
    fs::write(
        config_directory.join("config.toml"),
        format!(
            "version = 1\n\
             [contexts.empire.providers.ssh]\n\
             host_alias = \"empire-alpha\"\n\
             expected_remote_principal = \"researcher@example.invalid\"\n\
             control_path = \"{}\"\n",
            control_path.display()
        ),
    )
    .expect("fictional SSH user config is written");

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["status", "--context", "empire", "--provider", "ssh"])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("HOME", ssh_home.home())
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("report is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(
        normalize_human_observation_time(&stdout),
        "context: empire\n\
         provider: ssh\n\
         profile: empire-alpha\n\
         expected identity: researcher@example.invalid\n\
         observed identity: not observed\n\
         identity match: unverified\n\
         session usability: indeterminate\n\
         reason: insufficient_evidence\n\
         reauthentication need: unknown\n\
         evidence level: local_metadata\n\
         provider contacted: no\n\
         transport reuse: active\n\
         observed at unix: <observed_at_unix>\n"
    );
    assert!(stderr.is_empty());
}

#[test]
fn ssh_status_json_reports_transport_separately_from_session_axes() {
    let fixture = FixtureDirectory::new("status-ssh-json");
    let ssh_home = SshHomeFixture::new("json");
    let control_path = ssh_home.control_path();
    let _listener = UnixListener::bind(&control_path).expect("fixture control socket is created");
    let mut socket_permissions = fs::metadata(&control_path)
        .expect("control socket metadata is readable")
        .permissions();
    socket_permissions.set_mode(0o600);
    fs::set_permissions(&control_path, socket_permissions)
        .expect("control socket permissions are set");
    let bin_directory = ssh_home.configure_ssh(0);
    let config_directory = fixture.path.join("config").join("authmux");
    fs::create_dir_all(&config_directory).expect("config directory is created");
    fs::write(
        config_directory.join("config.toml"),
        format!(
            "version = 1\n\
             [contexts.empire.providers.ssh]\n\
             host_alias = \"empire-alpha\"\n\
             expected_remote_principal = \"researcher@example.invalid\"\n\
             control_path = \"{}\"\n",
            control_path.display()
        ),
    )
    .expect("fictional SSH user config is written");

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args([
            "status",
            "--context",
            "empire",
            "--provider",
            "ssh",
            "--json",
        ])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("HOME", ssh_home.home())
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("report is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(
        normalize_json_observation_time(&stdout),
        include_str!("fixtures/golden/status-ssh-json.json")
    );
    assert!(stderr.is_empty());
}

#[test]
fn ssh_status_reports_an_absent_control_socket_as_inactive() {
    let fixture = FixtureDirectory::new("status-ssh-inactive");
    let ssh_home = SshHomeFixture::new("inactive");
    let control_path = ssh_home.control_path();
    let bin_directory = ssh_home.configure_ssh(97);
    let config_directory = fixture.path.join("config").join("authmux");
    fs::create_dir_all(&config_directory).expect("config directory is created");
    fs::write(
        config_directory.join("config.toml"),
        format!(
            "version = 1\n\
             [contexts.empire.providers.ssh]\n\
             host_alias = \"empire-alpha\"\n\
             expected_remote_principal = \"researcher@example.invalid\"\n\
             control_path = \"{}\"\n",
            control_path.display()
        ),
    )
    .expect("fictional SSH user config is written");

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["status", "--context", "empire"])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("HOME", ssh_home.home())
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("report is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(stdout.contains("transport reuse: inactive\n"));
    assert!(stdout.contains("identity match: unverified\n"));
    assert!(stdout.contains("session usability: indeterminate\n"));
    assert!(stdout.contains("provider contacted: no\n"));
    assert!(stderr.is_empty());
}

#[test]
fn mixed_provider_status_requires_an_explicit_provider_before_any_probe() {
    let fixture = FixtureDirectory::new("status-mixed-provider");
    let (bin_directory, provider_marker) = fixture.configure(Some("111111111111"));
    fs::write(
        fixture.path.join("config/authmux/config.toml"),
        "version = 1\n\
         [contexts.crm.providers.aws]\n\
         profile = \"crm-development\"\n\
         expected_account = \"111111111111\"\n\
         [contexts.crm.providers.ssh]\n\
         host_alias = \"empire-alpha\"\n\
         expected_remote_principal = \"researcher@example.invalid\"\n",
    )
    .expect("mixed-provider user config is written");

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["status", "--context", "crm"])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("diagnostic is UTF-8"),
        "status requires --provider when the authentication context defines multiple providers\n"
    );
    assert!(
        !provider_marker.exists(),
        "status must not probe a provider"
    );
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

#[test]
fn malformed_local_metadata_is_not_exposed_by_json() {
    const SENSITIVE_FIXTURE: &str = "111111111111 unexpected-sensitive-metadata";
    let fixture = FixtureDirectory::new("status-malformed-json");
    let (bin_directory, sts_marker) = fixture.configure(Some(SENSITIVE_FIXTURE));

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["status", "--json", "--context", "crm"])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("report is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(stdout.contains("\"observed_identity\": null"));
    assert!(stdout.contains("\"reason\": \"provider_error\""));
    assert!(!stdout.contains(SENSITIVE_FIXTURE));
    assert!(!stderr.contains(SENSITIVE_FIXTURE));
    assert!(!sts_marker.exists(), "read-only status must not call STS");
}

struct FixtureDirectory {
    path: PathBuf,
}

struct SshHomeFixture {
    path: PathBuf,
}

impl SshHomeFixture {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after the Unix epoch")
            .as_nanos()
            % 1_000_000_000;
        let path = PathBuf::from("/private/tmp")
            .join(format!("amux-cs-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(path.join("home/.ssh")).expect("SSH fixture directory is created");
        let mut permissions = fs::metadata(path.join("home/.ssh"))
            .expect("SSH directory metadata is readable")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path.join("home/.ssh"), permissions)
            .expect("SSH directory permissions are set");
        Self { path }
    }

    fn home(&self) -> PathBuf {
        self.path.join("home")
    }

    fn control_path(&self) -> PathBuf {
        self.path.join("home/.ssh/empire.sock")
    }

    fn configure_ssh(&self, exit_code: i32) -> PathBuf {
        let bin_directory = self.path.join("bin");
        fs::create_dir(&bin_directory).expect("SSH fixture bin directory is created");
        let ssh = bin_directory.join("ssh");
        fs::write(&ssh, format!("#!/bin/sh\nexit {exit_code}\n"))
            .expect("fictional ssh is written");
        let mut permissions = fs::metadata(&ssh)
            .expect("fictional ssh metadata is readable")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&ssh, permissions).expect("fictional ssh is executable");
        bin_directory
    }
}

impl Drop for SshHomeFixture {
    fn drop(&mut self) {
        remove_fixture(&self.path);
    }
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
        self.configure_settings(account, None)
    }

    fn configure_login_session(&self, login_session: &str) -> (PathBuf, PathBuf) {
        self.configure_settings(None, Some(login_session))
    }

    fn configure_settings(
        &self,
        account: Option<&str>,
        login_session: Option<&str>,
    ) -> (PathBuf, PathBuf) {
        let bin_directory = self.path.join("bin");
        let config_directory = self.path.join("config").join("authmux");
        fs::create_dir_all(&bin_directory).expect("fixture bin directory is created");
        fs::create_dir_all(&config_directory).expect("fixture config directory is created");

        let sts_marker = self.path.join("sts-ran");
        let sso_result = account.map_or_else(
            || "exit 1".to_owned(),
            |account| format!("printf '{account}\\n'; exit 0"),
        );
        let login_result = login_session.map_or_else(
            || "exit 1".to_owned(),
            |session| format!("printf '{session}\\n'; exit 0"),
        );
        let aws = bin_directory.join("aws");
        fs::write(
            &aws,
            format!(
                "#!/bin/sh\n\
                 if [ \"$1\" = \"sts\" ]; then touch '{}'; exit 97; fi\n\
                 if [ \"$1 $2 $3 $4 $5\" = \"configure get sso_account_id --profile crm-development\" ]; then {sso_result}; fi\n\
                 if [ \"$1 $2 $3 $4 $5\" = \"configure get login_session --profile crm-development\" ]; then {login_result}; fi\n\
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

fn normalize_human_observation_time(report: &str) -> String {
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

fn normalize_json_observation_time(report: &str) -> String {
    report
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("\"observed_at_unix\": ") {
                "      \"observed_at_unix\": 0"
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

#![cfg(unix)]

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn gcloud_child_runs_with_matching_protected_selection_and_preserves_exit_code() {
    let fixture = GcpExecFixture::new("gcloud-match");
    let gcloud = fixture.write_child("gcloud", 23);

    let output = fixture.run(&gcloud);

    let stdout = String::from_utf8(output.stdout).expect("child output is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(23), "stderr: {stderr}");
    assert_eq!(
        stdout,
        format!(
            "CLOUDSDK_CONFIG={}\n\
             CLOUDSDK_ACTIVE_CONFIG_NAME=crm-research\n\
             CLOUDSDK_CORE_DISABLE_PROMPTS=1\n\
             CLOUDSDK_CORE_DISABLE_FILE_LOGGING=1\n\
             CLOUDSDK_CORE_DISABLE_USAGE_REPORTING=1\n\
             CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK=1\n",
            fixture.gcloud_dir().display()
        )
    );
    assert!(stderr.is_empty());
}

#[test]
fn gcloud_child_is_blocked_when_identity_or_project_does_not_match() {
    for (label, account, project, expected_message) in [
        (
            "identity-mismatch",
            "other@example.test",
            "fictional-project",
            "refusing child execution: expected GCP identity does not match the protected local gcloud selection\n",
        ),
        (
            "project-mismatch",
            "researcher@example.test",
            "other-project",
            "refusing child execution: expected GCP project does not match the protected local gcloud selection\n",
        ),
    ] {
        let fixture = GcpExecFixture::new(label);
        fixture.write_named_configuration(account, project);
        let marker = fixture.path.join("child-ran");
        let gcloud = fixture.write_marker_child("gcloud", &marker);

        let output = fixture.run(&gcloud);

        assert_eq!(output.status.code(), Some(3));
        assert_eq!(
            String::from_utf8(output.stderr).expect("diagnostic is UTF-8"),
            expected_message
        );
        assert!(!marker.exists(), "mismatched selection must block child");
    }
}

#[test]
fn non_gcloud_child_requires_an_explicit_adc_plane() {
    let fixture = GcpExecFixture::new("adc-required");
    let marker = fixture.path.join("child-ran");
    let child = fixture.write_marker_child("sdk-client", &marker);

    let output = fixture.run(&child);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).expect("diagnostic is UTF-8"),
        "refusing child execution: non-gcloud GCP children require an explicit ADC credential-file plane\n"
    );
    assert!(!marker.exists(), "child without ADC must not run");
}

#[test]
fn non_gcloud_child_runs_with_protected_adc_and_no_ambient_gcp_selection() {
    let fixture = GcpExecFixture::new("adc-match");
    fixture.add_adc_plane(true);
    let child = fixture.write_adc_environment_child("sdk-client", 31);

    let output = fixture.run(&child);

    let stdout = String::from_utf8(output.stdout).expect("child output is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(31), "stderr: {stderr}");
    assert_eq!(
        stdout,
        format!(
            "GOOGLE_APPLICATION_CREDENTIALS={}\n\
             GOOGLE_CLOUD_PROJECT=\n\
             GCLOUD_PROJECT=\n\
             CLOUDSDK_CORE_PROJECT=\n",
            fixture.adc_file().display()
        )
    );
    assert!(stderr.is_empty());
}

#[test]
fn non_gcloud_child_is_blocked_when_declared_adc_file_is_missing() {
    let fixture = GcpExecFixture::new("adc-missing");
    fixture.add_adc_plane(false);
    let marker = fixture.path.join("child-ran");
    let child = fixture.write_marker_child("sdk-client", &marker);

    let output = fixture.run(&child);

    assert_eq!(output.status.code(), Some(4));
    assert_eq!(
        String::from_utf8(output.stderr).expect("diagnostic is UTF-8"),
        "refusing child execution: protected ADC credential-file selection is unavailable\n"
    );
    assert!(!marker.exists(), "child with missing ADC must not run");
}

#[test]
fn mixed_provider_context_is_blocked_before_gcp_observation_or_child_spawn() {
    let fixture = GcpExecFixture::new("mixed-provider");
    fixture.add_aws_plane();
    fixture.remove_named_configuration();
    let marker = fixture.path.join("child-ran");
    let gcloud = fixture.write_marker_child("gcloud", &marker);

    let output = fixture.run(&gcloud);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).expect("diagnostic is UTF-8"),
        "refusing child execution: GCP execution cannot yet be composed with another provider\n"
    );
    assert!(!marker.exists(), "mixed-provider child must not run");
}

#[test]
fn malformed_secret_shaped_gcloud_metadata_is_never_rendered() {
    let fixture = GcpExecFixture::new("secret-shaped-selection");
    let seeded_secret = "ghp_fictional_provider_output";
    fixture.write_named_configuration(seeded_secret, "fictional-project");
    let marker = fixture.path.join("child-ran");
    let gcloud = fixture.write_marker_child("gcloud", &marker);

    let output = fixture.run(&gcloud);

    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(
        stderr,
        "refusing child execution: protected local gcloud selection evidence is unavailable\n"
    );
    assert!(!stderr.contains(seeded_secret));
    assert!(!marker.exists(), "malformed selection must block child");
}

#[test]
fn gcp_child_termination_signal_is_preserved() {
    let fixture = GcpExecFixture::new("signal");
    fixture.add_adc_plane(true);
    let child = fixture.write_signaling_child("sdk-client");

    let output = fixture.run(&child);

    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&output.status),
        Some(15)
    );
    assert!(output.stderr.is_empty());
}

struct GcpExecFixture {
    path: PathBuf,
}

impl GcpExecFixture {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "authmux-cli-gcp-exec-{label}-{}-{unique}",
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

    fn configure(&self) {
        for directory in [
            self.home(),
            self.home().join(".config"),
            self.gcloud_dir(),
            self.gcloud_dir().join("configurations"),
            self.authmux_config_root(),
            self.authmux_config_root().join("authmux"),
            self.path.join("bin"),
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
        fs::write(
            self.authmux_config_root().join("authmux/config.toml"),
            format!(
                "version = 1\n\
                 [contexts.crm.providers.gcp.gcloud]\n\
                 config_dir = \"{}\"\n\
                 configuration = \"crm-research\"\n\
                 expected_principal = \"researcher@example.test\"\n\
                 expected_project = \"fictional-project\"\n",
                self.gcloud_dir().display()
            ),
        )
        .expect("authmux user configuration is written");
    }

    fn write_named_configuration(&self, account: &str, project: &str) {
        let named = self.gcloud_dir().join("configurations/config_crm-research");
        fs::write(
            &named,
            format!("[core]\naccount = {account}\nproject = {project}\n"),
        )
        .expect("fictional named configuration is rewritten");
        set_mode(&named, 0o600);
    }

    fn remove_named_configuration(&self) {
        fs::remove_file(self.gcloud_dir().join("configurations/config_crm-research"))
            .expect("fictional named configuration is removed");
    }

    fn adc_file(&self) -> PathBuf {
        self.gcloud_dir().join("adc/crm.json")
    }

    fn add_adc_plane(&self, create_file: bool) {
        let adc_directory = self.gcloud_dir().join("adc");
        fs::create_dir_all(&adc_directory).expect("ADC directory is created");
        set_mode(&adc_directory, 0o700);
        if create_file {
            fs::write(self.adc_file(), "fictional contents are never opened")
                .expect("fictional ADC file is written");
            set_mode(&self.adc_file(), 0o600);
        }
        let config = self.authmux_config_root().join("authmux/config.toml");
        let mut source = fs::read_to_string(&config).expect("authmux config is readable");
        write!(
            source,
            "[contexts.crm.providers.gcp.adc]\n\
             mode = \"credential_file\"\n\
             credential_file = \"{}\"\n\
             expected_principal = \"workload@example.test\"\n",
            self.adc_file().display()
        )
        .expect("writing to a String cannot fail");
        fs::write(config, source).expect("ADC plane is added to authmux config");
    }

    fn add_aws_plane(&self) {
        let config = self.authmux_config_root().join("authmux/config.toml");
        let mut source = fs::read_to_string(&config).expect("authmux config is readable");
        source.push_str(
            "[contexts.crm.providers.aws]\n\
             profile = \"crm-development\"\n\
             expected_account = \"111111111111\"\n",
        );
        fs::write(config, source).expect("AWS plane is added to authmux config");
    }

    fn write_child(&self, name: &str, exit_code: i32) -> PathBuf {
        let child = self.path.join("bin").join(name);
        fs::write(
            &child,
            format!(
                "#!/bin/sh\n\
                 printf 'CLOUDSDK_CONFIG=%s\\n' \"$CLOUDSDK_CONFIG\"\n\
                 printf 'CLOUDSDK_ACTIVE_CONFIG_NAME=%s\\n' \"$CLOUDSDK_ACTIVE_CONFIG_NAME\"\n\
                 printf 'CLOUDSDK_CORE_DISABLE_PROMPTS=%s\\n' \"$CLOUDSDK_CORE_DISABLE_PROMPTS\"\n\
                 printf 'CLOUDSDK_CORE_DISABLE_FILE_LOGGING=%s\\n' \"$CLOUDSDK_CORE_DISABLE_FILE_LOGGING\"\n\
                 printf 'CLOUDSDK_CORE_DISABLE_USAGE_REPORTING=%s\\n' \"$CLOUDSDK_CORE_DISABLE_USAGE_REPORTING\"\n\
                 printf 'CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK=%s\\n' \"$CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK\"\n\
                 exit {exit_code}\n"
            ),
        )
        .expect("fictional child is written");
        set_mode(&child, 0o700);
        child
    }

    fn write_marker_child(&self, name: &str, marker: &Path) -> PathBuf {
        let child = self.path.join("bin").join(name);
        fs::write(
            &child,
            format!("#!/bin/sh\n/usr/bin/touch '{}'\nexit 0\n", marker.display()),
        )
        .expect("fictional marker child is written");
        set_mode(&child, 0o700);
        child
    }

    fn write_adc_environment_child(&self, name: &str, exit_code: i32) -> PathBuf {
        let child = self.path.join("bin").join(name);
        fs::write(
            &child,
            format!(
                "#!/bin/sh\n\
                 printf 'GOOGLE_APPLICATION_CREDENTIALS=%s\\n' \"$GOOGLE_APPLICATION_CREDENTIALS\"\n\
                 printf 'GOOGLE_CLOUD_PROJECT=%s\\n' \"$GOOGLE_CLOUD_PROJECT\"\n\
                 printf 'GCLOUD_PROJECT=%s\\n' \"$GCLOUD_PROJECT\"\n\
                 printf 'CLOUDSDK_CORE_PROJECT=%s\\n' \"$CLOUDSDK_CORE_PROJECT\"\n\
                 exit {exit_code}\n"
            ),
        )
        .expect("fictional ADC child is written");
        set_mode(&child, 0o700);
        child
    }

    fn write_signaling_child(&self, name: &str) -> PathBuf {
        let child = self.path.join("bin").join(name);
        fs::write(&child, "#!/bin/sh\nkill -TERM $$\n")
            .expect("fictional signaling child is written");
        set_mode(&child, 0o700);
        child
    }

    fn run(&self, child: &Path) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_authmux"))
            .args(["exec", "--context", "crm", "--"])
            .arg(child)
            .env("HOME", self.home())
            .env("XDG_CONFIG_HOME", self.authmux_config_root())
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.path.join("bin").display()),
            )
            .env("GOOGLE_APPLICATION_CREDENTIALS", "/ambient/credential.json")
            .env("GOOGLE_CLOUD_PROJECT", "ambient-project")
            .env("GCLOUD_PROJECT", "ambient-project")
            .env("CLOUDSDK_CORE_PROJECT", "ambient-project")
            .output()
            .expect("authmux runs")
    }
}

impl Drop for GcpExecFixture {
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

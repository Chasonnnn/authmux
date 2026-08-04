#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn ssh_login_previews_the_target_and_delegates_to_openssh() {
    let fixture = LoginFixture::new("ssh-success");
    let bin_directory = fixture.configure_ssh(0);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "empire", "--provider", "ssh"])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .env("GH_TOKEN", "ghp_fictional_must_not_pass")
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(
        stdout,
        "login: empire\n\
         provider: ssh\n\
         host alias: empire-alpha\n\
         expected remote principal: researcher@example.invalid\n\
         native command: ssh empire-alpha\n\
         native argv: empire-alpha\n\
         inherited GH_TOKEN: absent\n\
         result: native login command exited successfully; remote session usability remains unverified\n"
    );
    assert!(stderr.is_empty());
}

#[test]
fn gcp_login_previews_selected_account_and_delegates_to_gcloud() {
    let fixture = LoginFixture::new("gcp-success");
    let bin_directory = fixture.configure_gcp(0);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "crm", "--provider", "gcp"])
        .env("HOME", fixture.path.join("home"))
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .env(
            "GOOGLE_APPLICATION_CREDENTIALS",
            "/ambient/credential-that-must-not-pass.json",
        )
        .env("CLOUDSDK_CORE_DISABLE_PROMPTS", "1")
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(
        stdout,
        format!(
            "login: crm\n\
             provider: gcp\n\
             credential plane: gcloud_cli\n\
             gcloud configuration: crm-research\n\
             expected gcloud identity: researcher@example.invalid\n\
             login account: researcher@example.invalid\n\
             native command: gcloud auth login researcher@example.invalid --brief --force\n\
             native argv: auth|login|researcher@example.invalid|--brief|--force\n\
             CLOUDSDK_CONFIG={}\n\
             CLOUDSDK_ACTIVE_CONFIG_NAME=crm-research\n\
             CLOUDSDK_CORE_DISABLE_PROMPTS=absent\n\
             CLOUDSDK_CORE_DISABLE_FILE_LOGGING=1\n\
             CLOUDSDK_CORE_DISABLE_USAGE_REPORTING=1\n\
             CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK=1\n\
             GOOGLE_APPLICATION_CREDENTIALS=absent\n\
             result: native GCP login command exited successfully; live session usability remains unverified\n",
            fixture.path.join("home/.config/gcloud").display()
        )
    );
    assert!(stderr.is_empty());
}

#[test]
fn single_provider_gcp_login_does_not_require_a_provider_flag() {
    let fixture = LoginFixture::new("gcp-implicit-provider");
    let bin_directory = fixture.configure_gcp(0);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "crm"])
        .env("HOME", fixture.path.join("home"))
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(
        String::from_utf8(output.stdout)
            .expect("stdout is UTF-8")
            .starts_with("login: crm\nprovider: gcp\n")
    );
}

#[test]
fn impersonated_gcp_login_authenticates_the_declared_source_account() {
    let fixture = LoginFixture::new("gcp-impersonation");
    let bin_directory = fixture.configure_impersonated_gcp(0);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "crm", "--provider", "gcp"])
        .env("HOME", fixture.path.join("home"))
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(stdout.contains("expected gcloud identity: workload@example.invalid\n"));
    assert!(stdout.contains("login account: researcher@example.invalid\n"));
    assert!(
        stdout.contains("native argv: auth|login|researcher@example.invalid|--brief|--force\n")
    );
}

#[test]
fn adc_only_context_refuses_gcloud_login_before_native_spawn() {
    let fixture = LoginFixture::new("gcp-adc-only");
    let bin_directory = fixture.configure_adc_only_gcp();

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "crm", "--provider", "gcp"])
        .env("HOME", fixture.path.join("home"))
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr is UTF-8"),
        "refusing GCP login: the context does not declare a gcloud CLI credential plane\n"
    );
    assert!(!fixture.path.join("gcloud-ran").exists());
}

#[test]
fn gcp_login_preserves_native_failure_without_claiming_success() {
    let fixture = LoginFixture::new("gcp-native-failure");
    let bin_directory = fixture.configure_gcp(42);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "crm", "--provider", "gcp"])
        .env("HOME", fixture.path.join("home"))
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    assert_eq!(output.status.code(), Some(42));
    assert!(stdout.starts_with("login: crm\nprovider: gcp\n"));
    assert!(!stdout.contains("exited successfully"));
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr is UTF-8"),
        "native GCP login command exited with status 42\n"
    );
}

#[test]
fn gcp_login_reports_a_missing_native_executable_without_provider_output() {
    let fixture = LoginFixture::new("gcp-missing-executable");
    fixture.configure_gcp(0);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "crm", "--provider", "gcp"])
        .env("HOME", fixture.path.join("home"))
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", fixture.path.join("missing-bin"))
        .output()
        .expect("authmux runs");

    assert_eq!(output.status.code(), Some(126));
    assert!(
        String::from_utf8(output.stdout)
            .expect("stdout is UTF-8")
            .starts_with("login: crm\nprovider: gcp\n")
    );
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr is UTF-8"),
        "child execution failed: could not start child process (entity not found)\n"
    );
    assert!(!fixture.path.join("gcloud-ran").exists());
}

#[test]
fn gcp_login_preserves_native_termination_signal() {
    let fixture = LoginFixture::new("gcp-signal");
    let bin_directory = fixture.configure_signaling_gcp();

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "crm", "--provider", "gcp"])
        .env("HOME", fixture.path.join("home"))
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&output.status),
        Some(15)
    );
    assert!(output.stderr.is_empty());
    assert!(
        !String::from_utf8(output.stdout)
            .expect("stdout is UTF-8")
            .contains("exited successfully")
    );
}

#[test]
fn ssh_login_returns_the_native_failure_without_claiming_authentication() {
    let fixture = LoginFixture::new("ssh-failure");
    let bin_directory = fixture.configure_ssh(42);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "empire", "--provider", "ssh"])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(42), "stderr: {stderr}");
    assert!(stdout.starts_with("login: empire\nprovider: ssh\n"));
    assert!(!stdout.contains("exited successfully"));
    assert_eq!(stderr, "native SSH login command exited with status 42\n");
}

#[test]
fn mixed_context_login_requires_an_explicit_provider_before_spawn() {
    let fixture = LoginFixture::new("mixed-ambiguous");
    let bin_directory = fixture.configure_mixed();

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "mixed"])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert_eq!(
        stderr,
        "login requires --provider when the authentication context defines multiple providers\n"
    );
    assert!(!fixture.path.join("ssh-ran").exists());
}

struct LoginFixture {
    path: PathBuf,
}

impl LoginFixture {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "authmux-login-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("fixture directory is created");
        Self { path }
    }

    fn configure_ssh(&self, exit_code: i32) -> PathBuf {
        self.write_config(
            "version = 1\n\
             [contexts.empire]\n\
             [contexts.empire.providers.ssh]\n\
             host_alias = \"empire-alpha\"\n\
             expected_remote_principal = \"researcher@example.invalid\"\n",
        );
        self.write_fake_ssh(exit_code)
    }

    fn configure_gcp(&self, exit_code: i32) -> PathBuf {
        let home = self.path.join("home");
        fs::create_dir_all(home.join(".config/gcloud"))
            .expect("fictional gcloud directory is created");
        self.write_config(&format!(
            "version = 1\n\
             [contexts.crm.providers.gcp.gcloud]\n\
             config_dir = \"{}\"\n\
             configuration = \"crm-research\"\n\
             expected_principal = \"researcher@example.invalid\"\n\
             expected_project = \"fictional-project\"\n",
            home.join(".config/gcloud").display()
        ));
        self.write_fake_gcloud(exit_code)
    }

    fn configure_impersonated_gcp(&self, exit_code: i32) -> PathBuf {
        let home = self.path.join("home");
        fs::create_dir_all(home.join(".config/gcloud"))
            .expect("fictional gcloud directory is created");
        self.write_config(&format!(
            "version = 1\n\
             [contexts.crm.providers.gcp.gcloud]\n\
             config_dir = \"{}\"\n\
             configuration = \"crm-research\"\n\
             expected_principal = \"workload@example.invalid\"\n\
             expected_source_account = \"researcher@example.invalid\"\n\
             expected_project = \"fictional-project\"\n",
            home.join(".config/gcloud").display()
        ));
        self.write_fake_gcloud(exit_code)
    }

    fn configure_adc_only_gcp(&self) -> PathBuf {
        let home = self.path.join("home");
        let adc_file = home.join(".config/gcloud/adc/crm.json");
        fs::create_dir_all(adc_file.parent().expect("ADC fixture has a parent"))
            .expect("fictional ADC directory is created");
        fs::write(&adc_file, "fictional contents are never opened")
            .expect("fictional ADC file is written");
        self.write_config(&format!(
            "version = 1\n\
             [contexts.crm.providers.gcp.adc]\n\
             mode = \"credential_file\"\n\
             credential_file = \"{}\"\n\
             expected_principal = \"workload@example.invalid\"\n",
            adc_file.display()
        ));
        self.write_fake_gcloud(0)
    }

    fn configure_signaling_gcp(&self) -> PathBuf {
        let directory = self.configure_gcp(0);
        let gcloud = directory.join("gcloud");
        fs::write(&gcloud, "#!/bin/sh\nkill -TERM $$\n")
            .expect("signaling gcloud fixture is written");
        let mut permissions = fs::metadata(&gcloud)
            .expect("signaling gcloud metadata is readable")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&gcloud, permissions).expect("signaling gcloud is executable");
        directory
    }

    fn configure_mixed(&self) -> PathBuf {
        self.write_config(
            "version = 1\n\
             [contexts.mixed]\n\
             [contexts.mixed.providers.aws]\n\
             profile = \"fictional-profile\"\n\
             expected_account = \"111111111111\"\n\
             [contexts.mixed.providers.ssh]\n\
             host_alias = \"empire-alpha\"\n\
             expected_remote_principal = \"researcher@example.invalid\"\n",
        );
        self.write_fake_ssh(0)
    }

    fn write_config(&self, source: &str) {
        let directory = self.path.join("config/authmux");
        fs::create_dir_all(&directory).expect("config directory is created");
        fs::write(directory.join("config.toml"), source).expect("user config is written");
    }

    fn write_fake_ssh(&self, exit_code: i32) -> PathBuf {
        let directory = self.path.join("bin");
        fs::create_dir_all(&directory).expect("bin directory is created");
        let ssh = directory.join("ssh");
        fs::write(
            &ssh,
            format!(
                "#!/bin/sh\n\
                 : > '{}'\n\
                 printf 'native argv: %s\\n' \"$1\"\n\
                 if [ -n \"${{GH_TOKEN+x}}\" ]; then printf 'inherited GH_TOKEN: present\\n'; else printf 'inherited GH_TOKEN: absent\\n'; fi\n\
                 exit {exit_code}\n",
                self.path.join("ssh-ran").display()
            ),
        )
        .expect("fake ssh is written");
        let mut permissions = fs::metadata(&ssh)
            .expect("fake ssh metadata is readable")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&ssh, permissions).expect("fake ssh is executable");
        directory
    }

    fn write_fake_gcloud(&self, exit_code: i32) -> PathBuf {
        let directory = self.path.join("bin");
        fs::create_dir_all(&directory).expect("bin directory is created");
        let gcloud = directory.join("gcloud");
        fs::write(
            &gcloud,
            format!(
                "#!/bin/sh\n\
                 : > '{}'\n\
                 printf 'native argv: %s|%s|%s|%s|%s\\n' \"$1\" \"$2\" \"$3\" \"$4\" \"$5\"\n\
                 printf 'CLOUDSDK_CONFIG=%s\\n' \"$CLOUDSDK_CONFIG\"\n\
                 printf 'CLOUDSDK_ACTIVE_CONFIG_NAME=%s\\n' \"$CLOUDSDK_ACTIVE_CONFIG_NAME\"\n\
                 if [ -n \"${{CLOUDSDK_CORE_DISABLE_PROMPTS+x}}\" ]; then printf 'CLOUDSDK_CORE_DISABLE_PROMPTS=present\\n'; else printf 'CLOUDSDK_CORE_DISABLE_PROMPTS=absent\\n'; fi\n\
                 printf 'CLOUDSDK_CORE_DISABLE_FILE_LOGGING=%s\\n' \"$CLOUDSDK_CORE_DISABLE_FILE_LOGGING\"\n\
                 printf 'CLOUDSDK_CORE_DISABLE_USAGE_REPORTING=%s\\n' \"$CLOUDSDK_CORE_DISABLE_USAGE_REPORTING\"\n\
                 printf 'CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK=%s\\n' \"$CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK\"\n\
                 if [ -n \"${{GOOGLE_APPLICATION_CREDENTIALS+x}}\" ]; then printf 'GOOGLE_APPLICATION_CREDENTIALS=present\\n'; else printf 'GOOGLE_APPLICATION_CREDENTIALS=absent\\n'; fi\n\
                 exit {exit_code}\n",
                self.path.join("gcloud-ran").display()
            ),
        )
        .expect("fake gcloud is written");
        let mut permissions = fs::metadata(&gcloud)
            .expect("fake gcloud metadata is readable")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&gcloud, permissions).expect("fake gcloud is executable");
        directory
    }
}

impl Drop for LoginFixture {
    fn drop(&mut self) {
        match fs::remove_dir_all(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("fixture cleanup failed: {error}"),
        }
    }
}

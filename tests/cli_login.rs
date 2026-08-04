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

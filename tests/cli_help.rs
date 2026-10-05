#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn help_works_without_configuration_or_provider_contact() {
    let fixture = HelpFixture::new("help");
    for arguments in [
        vec!["--help"],
        vec!["-h"],
        vec!["exec", "--help"],
        vec!["exec", "--context", "fictional", "--help"],
        vec!["login", "--help"],
        vec!["login", "fictional", "--provider", "aws", "-h"],
        vec!["status", "--help"],
        vec!["doctor", "--help"],
        vec!["context", "--help"],
        vec!["context", "list", "--help"],
        vec!["context", "show", "--help"],
        vec!["aws", "--help"],
        vec!["gh", "--help"],
        vec!["gcloud", "--help"],
        vec!["empireai", "--help"],
    ] {
        let output = fixture.run(&arguments);
        assert_eq!(output.status.code(), Some(0), "{arguments:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.starts_with("usage: authmux "), "{arguments:?}");
        assert!(stdout.contains("--help"), "{arguments:?}");
        assert!(output.stderr.is_empty(), "{arguments:?}");
    }
    assert!(!fixture.0.join("provider-ran").exists());
}

#[test]
fn version_reports_package_version_without_configuration_or_provider_contact() {
    let fixture = HelpFixture::new("version");
    for flag in ["--version", "-V"] {
        let output = fixture.run(&[flag]);
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("authmux {}\n", env!("CARGO_PKG_VERSION"))
        );
        assert!(output.stderr.is_empty());
    }
    assert!(!fixture.0.join("provider-ran").exists());
}

struct HelpFixture(PathBuf);

impl HelpFixture {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "authmux-help-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("authmux")).unwrap();
        fs::create_dir(root.join("bin")).unwrap();
        fs::write(root.join("authmux/config.toml"), "invalid TOML [").unwrap();
        for provider in ["aws", "gh", "gcloud", "ssh"] {
            let executable = root.join("bin").join(provider);
            fs::write(
                &executable,
                format!(
                    "#!/bin/sh\n/usr/bin/touch '{}'\nexit 99\n",
                    root.join("provider-ran").display()
                ),
            )
            .unwrap();
            fs::set_permissions(executable, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(root)
    }

    fn run(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_authmux"))
            .args(arguments)
            .current_dir(&self.0)
            .env_clear()
            .env("HOME", &self.0)
            .env("XDG_CONFIG_HOME", &self.0)
            .env("PATH", self.0.join("bin"))
            .output()
            .unwrap()
    }
}

impl Drop for HelpFixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

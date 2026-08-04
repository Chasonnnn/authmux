use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use authmux::{SecureProcessRunner, SshClientReadinessCheck};

#[test]
#[ignore = "requires an installed OpenSSH client but never contacts a host"]
fn installed_openssh_client_passes_the_local_readiness_gate() {
    let runner = SecureProcessRunner::for_authmux().expect("secure process runner is available");
    let readiness = SshClientReadinessCheck::new(runner)
        .observe()
        .expect("installed OpenSSH client is recognized");

    assert!(readiness.client_version().starts_with("OpenSSH_"));
    assert!(!readiness.provider_contacted());
}

#[test]
#[ignore = "requires an installed OpenSSH client but never contacts a host"]
fn installed_openssh_client_passes_provider_scoped_doctor() {
    let config = LiveSshConfig::new();
    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args([
            "doctor",
            "--context",
            "live-ssh",
            "--provider",
            "ssh",
            "--json",
        ])
        .env("XDG_CONFIG_HOME", config.xdg_config_home())
        .output()
        .expect("authmux SSH doctor starts");

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("SSH doctor returns valid JSON");
    assert_eq!(report["result"], "warning");
    assert_eq!(report["provider_contacted"], false);
    assert!(report["checks"].as_array().is_some_and(|checks| {
        checks
            .iter()
            .any(|check| check["id"] == "openssh_client" && check["outcome"] == "pass")
    }));
}

struct LiveSshConfig {
    root: PathBuf,
}

impl LiveSshConfig {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after the Unix epoch")
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("authmux-live-ssh-{}-{unique}", std::process::id()));
        let config_directory = root.join("authmux");
        fs::create_dir_all(&config_directory).expect("live SSH config directory is created");
        fs::write(
            config_directory.join("config.toml"),
            "version = 1\n\
             [contexts.live-ssh.providers.ssh]\n\
             host_alias = \"fictional-empire\"\n\
             expected_remote_principal = \"researcher@example.invalid\"\n",
        )
        .expect("live SSH authmux config is written");
        Self { root }
    }

    fn xdg_config_home(&self) -> &Path {
        &self.root
    }
}

impl Drop for LiveSshConfig {
    fn drop(&mut self) {
        match fs::remove_dir_all(&self.root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("live SSH config cleanup failed: {error}"),
        }
    }
}

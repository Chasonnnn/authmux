use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const PROFILE_VARIABLE: &str = "AUTHMUX_LIVE_AWS_PROFILE";
const ACCOUNT_VARIABLE: &str = "AUTHMUX_LIVE_AWS_EXPECTED_ACCOUNT";
const ACKNOWLEDGEMENT_VARIABLE: &str = "AUTHMUX_LIVE_AWS_ACKNOWLEDGE_CACHE_WRITES";
const CONTEXT: &str = "live-aws";

#[test]
#[ignore = "contacts AWS and may refresh provider-owned credential caches"]
fn configured_aws_context_completes_the_live_cli_workflow() {
    let profile = required_environment(PROFILE_VARIABLE);
    let expected_account = required_environment(ACCOUNT_VARIABLE);
    assert_eq!(
        std::env::var(ACKNOWLEDGEMENT_VARIABLE).as_deref(),
        Ok("1"),
        "set AUTHMUX_LIVE_AWS_ACKNOWLEDGE_CACHE_WRITES=1 to acknowledge native AWS cache writes"
    );
    let config = LiveConfig::new(&profile, &expected_account);
    let context = OsString::from(CONTEXT);

    let doctor = run_authmux(
        [OsString::from("doctor"), context_flag(), context.clone()],
        config.xdg_config_home(),
    );
    assert_success(&doctor, "doctor");

    let status = run_authmux(
        [
            OsString::from("status"),
            context_flag(),
            context.clone(),
            OsString::from("--json"),
        ],
        config.xdg_config_home(),
    );
    assert_success(&status, "status");
    let report: serde_json::Value =
        serde_json::from_slice(&status.stdout).expect("live status returns valid JSON");
    let observation = &report["observations"][0];
    assert_eq!(observation["identity_match"], "match");
    assert_eq!(observation["session_usability"], "indeterminate");
    assert_eq!(observation["evidence_level"], "local_metadata");
    assert_eq!(observation["provider_contacted"], false);

    let guarded_exec = run_authmux(
        [
            OsString::from("exec"),
            context_flag(),
            context,
            OsString::from("--"),
            OsString::from("/usr/bin/true"),
        ],
        config.xdg_config_home(),
    );
    assert_success(&guarded_exec, "guarded exec");
}

fn context_flag() -> OsString {
    OsString::from("--context")
}

fn run_authmux<const N: usize>(arguments: [OsString; N], xdg_config_home: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(arguments)
        .env("XDG_CONFIG_HOME", xdg_config_home)
        .output()
        .expect("authmux live integration command starts")
}

fn required_environment(name: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| panic!("set {name} for the live AWS profile"))
}

struct LiveConfig {
    root: PathBuf,
}

impl LiveConfig {
    fn new(profile: &str, expected_account: &str) -> Self {
        assert!(
            !profile.is_empty()
                && profile.len() <= 128
                && profile.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                }),
            "live AWS profile contains unsupported characters"
        );
        assert!(
            expected_account.len() == 12
                && expected_account.bytes().all(|byte| byte.is_ascii_digit()),
            "live AWS expected account must be 12 digits"
        );

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after the Unix epoch")
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("authmux-live-aws-{}-{unique}", std::process::id()));
        let config_directory = root.join("authmux");
        fs::create_dir_all(&config_directory).expect("live config directory is created");
        fs::write(
            config_directory.join("config.toml"),
            format!(
                "version = 1\n[contexts.{CONTEXT}.providers.aws]\nprofile = \"{profile}\"\nexpected_account = \"{expected_account}\"\n"
            ),
        )
        .expect("live authmux config is written");
        Self { root }
    }

    fn xdg_config_home(&self) -> &Path {
        &self.root
    }
}

impl Drop for LiveConfig {
    fn drop(&mut self) {
        match fs::remove_dir_all(&self.root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("live config cleanup failed: {error}"),
        }
    }
}

fn assert_success(output: &Output, step: &str) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "live AWS {step} failed with exit code {:?}; rerun the command directly for its sanitized diagnostic",
        output.status.code()
    );
}

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const PROFILE_VARIABLE: &str = "AUTHMUX_LIVE_AWS_PROFILE";
const ACCOUNT_VARIABLE: &str = "AUTHMUX_LIVE_AWS_EXPECTED_ACCOUNT";
const ACKNOWLEDGEMENT_VARIABLE: &str = "AUTHMUX_LIVE_AWS_ACKNOWLEDGE_CACHE_WRITES";
const SECOND_PROFILE_VARIABLE: &str = "AUTHMUX_LIVE_AWS_SECOND_PROFILE";
const SECOND_ACCOUNT_VARIABLE: &str = "AUTHMUX_LIVE_AWS_SECOND_EXPECTED_ACCOUNT";
const LOGIN_ACKNOWLEDGEMENT_VARIABLE: &str = "AUTHMUX_LIVE_AWS_ACKNOWLEDGE_LOGIN_MUTATION";
const CONTEXT: &str = "live-aws";
const SECOND_CONTEXT: &str = "live-aws-second";

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

#[test]
#[ignore = "opens an interactive AWS browser login and validates two provider-owned profiles"]
fn configured_aws_login_and_two_profiles_complete_the_live_workflow() {
    let profile = required_environment(PROFILE_VARIABLE);
    let expected_account = required_environment(ACCOUNT_VARIABLE);
    let second_profile = required_environment(SECOND_PROFILE_VARIABLE);
    let second_expected_account = required_environment(SECOND_ACCOUNT_VARIABLE);
    assert_ne!(
        profile, second_profile,
        "live AWS profiles must be distinct"
    );
    assert_eq!(
        std::env::var(LOGIN_ACKNOWLEDGEMENT_VARIABLE).as_deref(),
        Ok("1"),
        "set AUTHMUX_LIVE_AWS_ACKNOWLEDGE_LOGIN_MUTATION=1 to acknowledge native AWS login cache writes"
    );
    assert_eq!(
        std::env::var(ACKNOWLEDGEMENT_VARIABLE).as_deref(),
        Ok("1"),
        "set AUTHMUX_LIVE_AWS_ACKNOWLEDGE_CACHE_WRITES=1 to acknowledge native AWS cache writes"
    );
    let config = LiveConfig::new_pair(
        &profile,
        &expected_account,
        &second_profile,
        &second_expected_account,
    );

    let login = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", CONTEXT, "--provider", "aws"])
        .env("XDG_CONFIG_HOME", config.xdg_config_home())
        .status()
        .expect("authmux AWS login runs with the terminal attached");
    assert_eq!(
        login.code(),
        Some(0),
        "live AWS login failed; native provider output is not captured by the test"
    );

    assert_live_context(&config, CONTEXT);
    assert_live_context(&config, SECOND_CONTEXT);
}

fn assert_live_context(config: &LiveConfig, context: &str) {
    let doctor = run_authmux(
        [
            OsString::from("doctor"),
            context_flag(),
            OsString::from(context),
        ],
        config.xdg_config_home(),
    );
    assert_success(&doctor, "doctor");

    let status = run_authmux(
        [
            OsString::from("status"),
            context_flag(),
            OsString::from(context),
            OsString::from("--json"),
        ],
        config.xdg_config_home(),
    );
    assert_success(&status, "status");
    let report: serde_json::Value =
        serde_json::from_slice(&status.stdout).expect("live status returns valid JSON");
    let observation = &report["observations"][0];
    assert_ne!(observation["identity_match"], "mismatch");
    assert_eq!(observation["session_usability"], "indeterminate");
    assert_eq!(observation["evidence_level"], "local_metadata");
    assert_eq!(observation["provider_contacted"], false);

    let guarded_exec = run_authmux(
        [
            OsString::from("exec"),
            context_flag(),
            OsString::from(context),
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
        validate_profile(profile);
        validate_account(expected_account);

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

    fn new_pair(
        profile: &str,
        expected_account: &str,
        second_profile: &str,
        second_expected_account: &str,
    ) -> Self {
        validate_profile(profile);
        validate_account(expected_account);
        validate_profile(second_profile);
        validate_account(second_expected_account);

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after the Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "authmux-live-aws-pair-{}-{unique}",
            std::process::id()
        ));
        let config_directory = root.join("authmux");
        fs::create_dir_all(&config_directory).expect("live config directory is created");
        fs::write(
            config_directory.join("config.toml"),
            format!(
                "version = 1\n\
                 [contexts.{CONTEXT}.providers.aws]\n\
                 profile = \"{profile}\"\n\
                 expected_account = \"{expected_account}\"\n\
                 [contexts.{SECOND_CONTEXT}.providers.aws]\n\
                 profile = \"{second_profile}\"\n\
                 expected_account = \"{second_expected_account}\"\n"
            ),
        )
        .expect("paired live authmux config is written");
        Self { root }
    }

    fn xdg_config_home(&self) -> &Path {
        &self.root
    }
}

fn validate_profile(profile: &str) {
    assert!(
        !profile.is_empty()
            && profile.len() <= 128
            && profile
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
        "live AWS profile contains unsupported characters"
    );
}

fn validate_account(expected_account: &str) {
    assert!(
        expected_account.len() == 12 && expected_account.bytes().all(|byte| byte.is_ascii_digit()),
        "live AWS expected account must be 12 digits"
    );
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

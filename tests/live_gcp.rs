#![cfg(unix)]

use std::ffi::OsString;
use std::process::{Command, Output};

#[test]
#[ignore = "requires a user-owned authmux GCP context but never runs gcloud or contacts Google"]
fn configured_gcp_context_completes_the_live_local_workflow() {
    let context = required_environment("AUTHMUX_LIVE_GCP_CONTEXT");

    let status = run_authmux(&[
        OsString::from("status"),
        OsString::from("--context"),
        context.clone(),
        OsString::from("--provider"),
        OsString::from("gcp"),
        OsString::from("--json"),
    ]);
    assert_success(&status, "status");
    let document: serde_json::Value =
        serde_json::from_slice(&status.stdout).expect("live GCP status returns valid JSON");
    let observations = document["observations"]
        .as_array()
        .expect("live GCP status has observations");
    assert!(!observations.is_empty());
    assert!(observations.iter().all(|observation| {
        observation["provider"] == "gcp"
            && observation["provider_contacted"] == false
            && observation["session_usability"] == "indeterminate"
            && observation["evidence_level"] == "local_metadata"
            && observation["identity_match"] != "mismatch"
    }));

    let doctor = run_authmux(&[
        OsString::from("doctor"),
        OsString::from("--context"),
        context,
        OsString::from("--provider"),
        OsString::from("gcp"),
        OsString::from("--json"),
    ]);
    assert_success(&doctor, "doctor");
    let document: serde_json::Value =
        serde_json::from_slice(&doctor.stdout).expect("live GCP doctor returns valid JSON");
    assert_eq!(document["provider_contacted"], false);
    assert_ne!(document["result"], "fail");
}

#[test]
#[ignore = "contacts Google Cloud and may refresh or update provider-owned gcloud caches"]
fn configured_gcp_context_completes_the_live_exec_workflow() {
    let context = required_environment("AUTHMUX_LIVE_GCP_CONTEXT");
    let project = required_environment("AUTHMUX_LIVE_GCP_EXPECTED_PROJECT");
    assert_eq!(
        required_environment("AUTHMUX_LIVE_GCP_ACKNOWLEDGE_CACHE_WRITES"),
        "1",
        "live GCP exec requires explicit cache-write acknowledgement"
    );

    let output = run_authmux(&[
        OsString::from("exec"),
        OsString::from("--context"),
        context,
        OsString::from("--"),
        OsString::from("gcloud"),
        OsString::from("projects"),
        OsString::from("describe"),
        project.clone(),
        OsString::from("--format=value(projectId)"),
        OsString::from("--quiet"),
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "live GCP exec failed; provider output intentionally omitted"
    );
    let expected = [project.as_encoded_bytes(), b"\n"].concat();
    assert!(
        output.stdout == expected,
        "live GCP exec returned an unexpected project; provider output intentionally omitted"
    );
}

#[test]
#[ignore = "opens an interactive browser login and mutates provider-owned gcloud credential state"]
fn configured_gcp_context_completes_the_live_login_and_exec_workflow() {
    let context = required_environment("AUTHMUX_LIVE_GCP_CONTEXT");
    let project = required_environment("AUTHMUX_LIVE_GCP_EXPECTED_PROJECT");
    assert_eq!(
        required_environment("AUTHMUX_LIVE_GCP_ACKNOWLEDGE_LOGIN_MUTATION"),
        "1",
        "live GCP login requires explicit credential-state mutation acknowledgement"
    );

    let login = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", context.to_str().expect("context is Unicode")])
        .status()
        .expect("authmux login runs with the terminal attached");
    assert_eq!(
        login.code(),
        Some(0),
        "live GCP login failed; native provider output is not captured by the test"
    );

    let output = run_authmux(&[
        OsString::from("exec"),
        OsString::from("--context"),
        context,
        OsString::from("--"),
        OsString::from("gcloud"),
        OsString::from("projects"),
        OsString::from("describe"),
        project.clone(),
        OsString::from("--format=value(projectId)"),
        OsString::from("--quiet"),
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "post-login GCP exec failed; provider output intentionally omitted"
    );
    let expected = [project.as_encoded_bytes(), b"\n"].concat();
    assert!(
        output.stdout == expected,
        "post-login GCP exec returned an unexpected project; provider output intentionally omitted"
    );
}

fn required_environment(name: &str) -> OsString {
    std::env::var_os(name).unwrap_or_else(|| panic!("{name} must be set for the live GCP gate"))
}

fn run_authmux(arguments: &[OsString]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(arguments)
        .output()
        .expect("authmux runs")
}

fn assert_success(output: &Output, command: &str) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "{command} failed with sanitized stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

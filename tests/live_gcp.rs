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

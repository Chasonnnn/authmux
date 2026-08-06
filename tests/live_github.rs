#![cfg(unix)]

use std::ffi::OsString;
use std::process::Command;

const CONTEXT_VARIABLE: &str = "AUTHMUX_LIVE_GITHUB_CONTEXT";
const ACKNOWLEDGEMENT_VARIABLE: &str = "AUTHMUX_LIVE_GITHUB_ACKNOWLEDGE_PROVIDER_CONTACT";

#[test]
#[ignore = "contacts GitHub using a user-owned gh configuration"]
fn configured_github_context_completes_the_live_cli_workflow() {
    let context = required_environment(CONTEXT_VARIABLE);
    assert_eq!(
        std::env::var_os(ACKNOWLEDGEMENT_VARIABLE),
        Some(OsString::from("1")),
        "set {ACKNOWLEDGEMENT_VARIABLE}=1 to acknowledge read-only GitHub provider contact"
    );

    let doctor = authmux(&[
        OsString::from("doctor"),
        OsString::from("--context"),
        context.clone(),
        OsString::from("--provider"),
        OsString::from("github"),
        OsString::from("--json"),
    ]);
    assert!(doctor.status.success(), "GitHub doctor failed");

    let status = authmux(&[
        OsString::from("status"),
        OsString::from("--context"),
        context.clone(),
        OsString::from("--provider"),
        OsString::from("github"),
        OsString::from("--json"),
    ]);
    assert!(status.status.success(), "GitHub status failed");
    let document: serde_json::Value =
        serde_json::from_slice(&status.stdout).expect("GitHub status is valid JSON");
    assert_eq!(document["observations"][0]["identity_match"], "match");
    assert_eq!(document["observations"][0]["session_usability"], "usable");
    assert_eq!(
        document["observations"][0]["evidence_level"],
        "provider_validation"
    );

    let execution = authmux(&[
        OsString::from("exec"),
        OsString::from("--context"),
        context,
        OsString::from("--"),
        OsString::from("gh"),
        OsString::from("api"),
        OsString::from("user"),
        OsString::from("--jq"),
        OsString::from(".login"),
    ]);
    assert!(
        execution.status.success(),
        "guarded GitHub execution failed"
    );
}

fn authmux(arguments: &[OsString]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(arguments)
        .output()
        .expect("authmux runs")
}

fn required_environment(name: &str) -> OsString {
    std::env::var_os(name).unwrap_or_else(|| panic!("{name} is required"))
}

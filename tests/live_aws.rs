use std::ffi::OsString;
use std::process::{Command, ExitStatus};

const CONTEXT_VARIABLE: &str = "AUTHMUX_LIVE_AWS_CONTEXT";
const ACKNOWLEDGEMENT_VARIABLE: &str = "AUTHMUX_LIVE_AWS_ACKNOWLEDGE_CACHE_WRITES";

#[test]
#[ignore = "contacts AWS and may refresh provider-owned credential caches"]
fn configured_aws_context_completes_the_live_cli_workflow() {
    let context = std::env::var_os(CONTEXT_VARIABLE)
        .filter(|value| !value.is_empty())
        .expect("set AUTHMUX_LIVE_AWS_CONTEXT to an existing authmux context");
    assert_eq!(
        std::env::var(ACKNOWLEDGEMENT_VARIABLE).as_deref(),
        Ok("1"),
        "set AUTHMUX_LIVE_AWS_ACKNOWLEDGE_CACHE_WRITES=1 to acknowledge native AWS cache writes"
    );

    assert_success(
        run_authmux([OsString::from("doctor"), context_flag(), context.clone()]),
        "doctor",
    );
    assert_success(
        run_authmux([OsString::from("status"), context_flag(), context.clone()]),
        "status",
    );
    assert_success(
        run_authmux([
            OsString::from("exec"),
            context_flag(),
            context,
            OsString::from("--"),
            OsString::from("/usr/bin/true"),
        ]),
        "guarded exec",
    );
}

fn context_flag() -> OsString {
    OsString::from("--context")
}

fn run_authmux<const N: usize>(arguments: [OsString; N]) -> ExitStatus {
    Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(arguments)
        .output()
        .expect("authmux live integration command starts")
        .status
}

fn assert_success(status: ExitStatus, step: &str) {
    assert_eq!(
        status.code(),
        Some(0),
        "live AWS {step} failed with exit code {:?}; rerun the command directly for its sanitized diagnostic",
        status.code()
    );
}

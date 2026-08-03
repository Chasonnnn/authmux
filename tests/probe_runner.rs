use std::time::Duration;

use authmux::{CommandSpec, ExecutionSelection, ProbePolicy, ProbeRunner, SecureProcessRunner};

#[test]
fn missing_provider_executable_returns_a_sanitized_failure() {
    let runner = SecureProcessRunner::new(&[]).expect("empty inheritance allowlist is valid");
    let command = CommandSpec::new(
        "authmux-fixture-executable-does-not-exist",
        std::iter::empty::<&str>(),
    )
    .expect("fixture command is valid");
    let selection = ExecutionSelection::aws_profile("fictional");

    let failure = runner
        .probe(
            &command,
            &selection,
            ProbePolicy::bounded(Duration::from_secs(1), 1_024),
        )
        .expect_err("missing provider executable must fail safely");
    let diagnostic = failure.to_string();

    assert_eq!(
        diagnostic,
        "could not start provider probe (entity not found)"
    );
    assert!(!diagnostic.contains("authmux-fixture-executable"));
}

#[test]
fn provider_probe_is_killed_at_its_deadline() {
    let runner = SecureProcessRunner::new(&[]).expect("empty inheritance allowlist is valid");
    let command = CommandSpec::new("/bin/sleep", ["2"]).expect("fixture command is valid");
    let selection = ExecutionSelection::aws_profile("fictional");

    let failure = runner
        .probe(
            &command,
            &selection,
            ProbePolicy::bounded(Duration::from_millis(50), 1_024),
        )
        .expect_err("probe must not outlive its deadline");

    assert_eq!(failure.to_string(), "provider probe timed out after 50 ms");
}

#[test]
fn output_exactly_at_the_cap_is_not_reported_as_truncated() {
    let runner = SecureProcessRunner::new(&[]).expect("empty inheritance allowlist is valid");
    let command = CommandSpec::new("/usr/bin/printf", ["1234"]).expect("fixture command is valid");
    let selection = ExecutionSelection::aws_profile("fictional");

    let output = runner
        .probe(
            &command,
            &selection,
            ProbePolicy::bounded(Duration::from_secs(1), 4),
        )
        .expect("bounded probe should succeed");

    assert_eq!(output.stdout(), b"1234");
    assert!(!output.was_truncated());
}

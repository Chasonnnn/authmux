use authmux::{CommandSpec, ExecutionSelection, ProcessRunner, SecureProcessRunner};

#[test]
fn child_receives_selector_without_arbitrary_parent_environment() {
    let runner = SecureProcessRunner::new(&[]).expect("empty inheritance allowlist is valid");
    let command = CommandSpec::new(
        "/bin/sh",
        [
            "-c",
            "test \"$AWS_PROFILE\" = 'crm;still-literal' && test -z \"$CARGO_MANIFEST_DIR\"",
        ],
    )
    .expect("command is valid");
    let selection = ExecutionSelection::aws_profile("crm;still-literal");

    let outcome = runner
        .run(&command, &selection)
        .expect("child process should run");

    assert_eq!(outcome.exit_code(), Some(0));
    assert_eq!(outcome.signal(), None);
}

#[cfg(unix)]
#[test]
fn child_signal_is_preserved_as_a_typed_outcome() {
    let runner = SecureProcessRunner::new(&[]).expect("empty inheritance allowlist is valid");
    let command = CommandSpec::new("/bin/sh", ["-c", "kill -TERM $$"]).expect("command is valid");
    let selection = ExecutionSelection::aws_profile("fixture-profile");

    let outcome = runner
        .run(&command, &selection)
        .expect("signal termination is an execution outcome");

    assert_eq!(outcome.signal(), Some(15));
    assert_eq!(outcome.exit_code(), None);
}

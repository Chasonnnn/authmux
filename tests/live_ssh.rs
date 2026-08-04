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

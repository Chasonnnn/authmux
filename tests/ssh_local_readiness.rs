use std::time::Duration;

use authmux::{
    ExecutionSelection, ProbeOutput, ProbePolicy, ProbeRunner, ProviderFailure,
    SshClientReadinessCheck,
};

struct SshVersionFixture {
    output: ProbeOutput,
}

impl ProbeRunner for SshVersionFixture {
    fn probe(
        &self,
        command: &authmux::CommandSpec,
        selection: &ExecutionSelection,
        policy: ProbePolicy,
    ) -> Result<ProbeOutput, ProviderFailure> {
        assert_eq!(command.program(), "ssh");
        assert_eq!(command.arguments(), ["-V"]);
        assert!(selection.environment().is_empty());
        assert_eq!(policy.timeout(), Duration::from_secs(2));
        assert_eq!(policy.output_limit(), 4_096);
        Ok(self.output.clone())
    }
}

#[test]
fn openssh_version_is_retained_as_local_readiness_only() {
    let check = SshClientReadinessCheck::new(SshVersionFixture {
        output: ProbeOutput::exited(0, b"", b"OpenSSH_10.2p1, LibreSSL 3.3.6\n"),
    });

    let readiness = check
        .observe()
        .expect("supported OpenSSH version is recognized");

    assert_eq!(readiness.client_version(), "OpenSSH_10.2p1");
    assert!(!readiness.provider_contacted());
}

#[test]
fn malformed_version_output_is_rejected_without_echoing_it() {
    let seeded_output = "OpenSSH_10.2p1 ghp_fictional_sensitive_output";
    let check = SshClientReadinessCheck::new(SshVersionFixture {
        output: ProbeOutput::exited(0, b"", seeded_output.as_bytes()),
    });

    let failure = check
        .observe()
        .expect_err("unexpected version metadata must fail closed");
    let diagnostic = failure.to_string();

    assert_eq!(diagnostic, "OpenSSH version output was not recognized");
    assert!(!diagnostic.contains(seeded_output));
}

#[test]
fn unavailable_openssh_is_a_sanitized_local_failure() {
    let seeded_output = "fictional-sensitive-native-error";
    let check = SshClientReadinessCheck::new(SshVersionFixture {
        output: ProbeOutput::exited(255, b"", seeded_output.as_bytes()),
    });

    let failure = check
        .observe()
        .expect_err("nonzero version command must fail closed");
    let diagnostic = failure.to_string();

    assert_eq!(diagnostic, "OpenSSH client version could not be determined");
    assert!(!diagnostic.contains(seeded_output));
}

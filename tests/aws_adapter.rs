use std::time::Duration;

use authmux::{
    AuthenticationContext, AwsAdapter, EvidenceLevel, ExecutionSelection, IdentityMatch,
    ProbeOutput, ProbePolicy, ProbeRunner, ProviderAdapter, ProviderFailure, SessionUsability,
};

struct AwsIdentityFixture;

impl ProbeRunner for AwsIdentityFixture {
    fn probe(
        &self,
        command: &authmux::CommandSpec,
        selection: &ExecutionSelection,
        policy: ProbePolicy,
    ) -> Result<ProbeOutput, ProviderFailure> {
        assert_eq!(command.program(), "aws");
        assert_eq!(
            command.arguments(),
            [
                "sts",
                "get-caller-identity",
                "--query",
                "Account",
                "--output",
                "text",
                "--no-cli-pager",
            ]
        );
        assert_eq!(
            selection.environment(),
            [("AWS_PROFILE".into(), "crm-development".into())]
        );
        assert_eq!(policy.timeout(), Duration::from_secs(5));
        assert_eq!(policy.output_limit(), 4_096);

        Ok(ProbeOutput::exited(0, b"111111111111\n", b""))
    }
}

struct SensitiveFailureFixture;

impl ProbeRunner for SensitiveFailureFixture {
    fn probe(
        &self,
        _command: &authmux::CommandSpec,
        _selection: &ExecutionSelection,
        _policy: ProbePolicy,
    ) -> Result<ProbeOutput, ProviderFailure> {
        Ok(ProbeOutput::exited(
            1,
            b"",
            b"provider rejected AKIA1111111111111111",
        ))
    }
}

#[test]
fn supported_aws_identity_probe_becomes_a_usable_observation() {
    let adapter = AwsAdapter::new(AwsIdentityFixture);
    let context = AuthenticationContext::aws("crm", "crm-development", "111111111111")
        .expect("fictional context is valid");

    let observation = adapter
        .observe(&context)
        .expect("fixture is a supported AWS response");

    assert_eq!(observation.observed_identity().account(), "111111111111");
    assert_eq!(observation.identity_match(), IdentityMatch::Unverified);
    assert_eq!(observation.usability(), SessionUsability::Usable);
    assert_eq!(
        observation.evidence_level(),
        EvidenceLevel::ProviderValidation
    );
    assert_eq!(observation.reason(), None);
}

#[test]
fn provider_failure_does_not_expose_native_output() {
    let adapter = AwsAdapter::new(SensitiveFailureFixture);
    let context = AuthenticationContext::aws("crm", "crm-development", "111111111111")
        .expect("fictional context is valid");

    let failure = adapter
        .observe(&context)
        .expect_err("fictional provider failure must remain sanitized");
    let diagnostic = failure.to_string();

    assert_eq!(
        diagnostic,
        "AWS identity observation failed; run `authmux login` for this context"
    );
    assert!(!diagnostic.contains("AKIA1111111111111111"));
}

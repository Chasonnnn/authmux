use std::time::Duration;

use authmux::{
    AuthenticationContext, AwsAdapter, EvidenceLevel, ExecutionSelection, IdentityMatch,
    ObservationReason, ProbeOutput, ProbePolicy, ProbeRunner, ProviderAdapter, ProviderFailure,
    ReauthenticationNeed, SessionUsability,
};

struct AwsIdentityFixture {
    exit_code: i32,
    stdout: &'static [u8],
    stderr: &'static [u8],
}

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
                "--no-cli-auto-prompt",
            ]
        );
        assert_eq!(
            selection.environment(),
            [("AWS_PROFILE".into(), "crm-development".into())]
        );
        assert_eq!(policy.timeout(), Duration::from_secs(5));
        assert_eq!(policy.output_limit(), 4_096);

        Ok(ProbeOutput::exited(
            self.exit_code,
            self.stdout,
            self.stderr,
        ))
    }
}

#[test]
fn supported_aws_identity_probe_becomes_a_usable_observation() {
    let adapter = AwsAdapter::new(AwsIdentityFixture {
        exit_code: 0,
        stdout: include_bytes!("fixtures/aws/success.stdout"),
        stderr: b"",
    });
    let context = AuthenticationContext::aws("crm", "crm-development", "111111111111")
        .expect("fictional context is valid");

    let observation = adapter
        .observe(&context)
        .expect("fixture is a supported AWS response");

    assert_eq!(
        observation
            .observed_identity()
            .expect("provider validation includes identity")
            .account(),
        "111111111111"
    );
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
    let adapter = AwsAdapter::new(AwsIdentityFixture {
        exit_code: 1,
        stdout: b"",
        stderr: include_bytes!("fixtures/aws/sensitive.stderr"),
    });
    let context = AuthenticationContext::aws("crm", "crm-development", "111111111111")
        .expect("fictional context is valid");

    let failure = adapter
        .observe(&context)
        .expect_err("fictional provider failure must remain sanitized");
    let diagnostic = failure.to_string();

    assert_eq!(
        diagnostic,
        "AWS identity observation failed without evidence that Reauthentication is required"
    );
    assert!(!diagnostic.contains("AKIA1111111111111111"));
    assert!(!diagnostic.contains("/fictional/private/path"));
}

#[test]
fn recorded_expired_and_missing_sessions_require_explicit_reauthentication() {
    let fixtures = [
        (
            include_bytes!("fixtures/aws/expired.stderr").as_slice(),
            ObservationReason::Expired,
        ),
        (
            include_bytes!("fixtures/aws/missing-login.stderr").as_slice(),
            ObservationReason::Missing,
        ),
    ];
    let context = AuthenticationContext::aws("crm", "crm-development", "111111111111")
        .expect("fictional context is valid");

    for (stderr, expected_reason) in fixtures {
        let adapter = AwsAdapter::new(AwsIdentityFixture {
            exit_code: 1,
            stdout: b"",
            stderr,
        });
        let observation = adapter
            .observe(&context)
            .expect("recognized Session evidence is normalized");

        assert_eq!(observation.usability(), SessionUsability::Unusable);
        assert_eq!(observation.reason(), Some(expected_reason));
        assert_eq!(
            observation.reauthentication_need(),
            ReauthenticationNeed::Required
        );
        assert_eq!(
            observation.evidence_level(),
            EvidenceLevel::ProviderValidation
        );
        assert!(observation.observed_identity().is_none());
    }
}

#[test]
fn unreachable_provider_evidence_remains_a_sanitized_failure() {
    let adapter = AwsAdapter::new(AwsIdentityFixture {
        exit_code: 1,
        stdout: b"",
        stderr: include_bytes!("fixtures/aws/unreachable.stderr"),
    });
    let context = AuthenticationContext::aws("crm", "crm-development", "111111111111")
        .expect("fictional context is valid");

    let failure = adapter
        .observe(&context)
        .expect_err("unreachable is not evidence that login is required");

    assert_eq!(
        failure.to_string(),
        "AWS identity observation could not reach the provider; allow network access and retry"
    );
    assert!(!failure.to_string().contains("identity.fixture.invalid"));
}

#[test]
fn malformed_success_fixture_is_rejected_without_echoing_output() {
    let malformed = include_bytes!("fixtures/aws/malformed.stdout");
    let adapter = AwsAdapter::new(AwsIdentityFixture {
        exit_code: 0,
        stdout: malformed,
        stderr: b"",
    });
    let context = AuthenticationContext::aws("crm", "crm-development", "111111111111")
        .expect("fictional context is valid");

    let failure = adapter
        .observe(&context)
        .expect_err("malformed provider output must fail closed");
    let diagnostic = failure.to_string();

    assert_eq!(
        diagnostic,
        "AWS account identity must contain exactly 12 digits"
    );
    assert!(!diagnostic.contains("unexpected-extra-field"));
}

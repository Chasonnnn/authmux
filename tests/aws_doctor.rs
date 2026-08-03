use authmux::{
    AuthenticationContext, AwsDoctor, DoctorOutcome, ExecutionSelection, ProbeOutput, ProbePolicy,
    ProbeRunner, ProviderFailure,
};

struct DoctorFixture {
    version: Result<ProbeOutput, ProviderFailure>,
    metadata: Result<ProbeOutput, ProviderFailure>,
}

impl ProbeRunner for DoctorFixture {
    fn probe(
        &self,
        command: &authmux::CommandSpec,
        selection: &ExecutionSelection,
        _policy: ProbePolicy,
    ) -> Result<ProbeOutput, ProviderFailure> {
        assert_eq!(command.program(), "aws");
        assert!(selection.environment().is_empty());
        if command.arguments() == ["--version"] {
            self.version.clone()
        } else {
            assert_eq!(
                command.arguments(),
                [
                    "configure",
                    "get",
                    "sso_account_id",
                    "--profile",
                    "crm-development",
                ]
            );
            self.metadata.clone()
        }
    }
}

#[test]
fn malformed_version_output_becomes_a_sanitized_failed_check() {
    let seeded_output = "ghp_fictional_sensitive_version_output";
    let fixture = DoctorFixture {
        version: Ok(ProbeOutput::exited(0, seeded_output.as_bytes(), b"")),
        metadata: Ok(ProbeOutput::exited(0, b"111111111111\n", b"")),
    };
    let context = AuthenticationContext::aws("crm", "crm-development", "111111111111")
        .expect("fictional context is valid");

    let result = AwsDoctor::new(&fixture, &fixture).diagnose(&context);
    let diagnostic = format!("{result:?}");

    assert_eq!(result.outcome(), DoctorOutcome::Fail);
    assert!(
        result
            .checks()
            .iter()
            .any(|check| check.summary() == "AWS CLI version output was not recognized")
    );
    assert!(!diagnostic.contains(seeded_output));
}

#[test]
fn absent_profile_account_metadata_is_a_warning_not_a_false_failure() {
    let fixture = DoctorFixture {
        version: Ok(ProbeOutput::exited(
            0,
            b"aws-cli/2.36.11 Python/3.14.6 fictional/1.0\n",
            b"",
        )),
        metadata: Ok(ProbeOutput::exited(1, b"", b"fictional missing setting")),
    };
    let context = AuthenticationContext::aws("crm", "crm-development", "111111111111")
        .expect("fictional context is valid");

    let result = AwsDoctor::new(&fixture, &fixture).diagnose(&context);

    assert_eq!(result.outcome(), DoctorOutcome::Warning);
    assert!(result.checks().iter().any(|check| {
        check.outcome() == DoctorOutcome::Warning
            && check.summary() == "AWS profile has no supported local account metadata"
    }));
}

#[test]
fn unavailable_aws_cli_is_reported_without_provider_failure_text() {
    let provider_failure = ProviderFailure::sanitized(
        "could not start provider probe (NotFound) fictional-sensitive-path",
    );
    let fixture = DoctorFixture {
        version: Err(provider_failure.clone()),
        metadata: Err(provider_failure),
    };
    let context = AuthenticationContext::aws("crm", "crm-development", "111111111111")
        .expect("fictional context is valid");

    let result = AwsDoctor::new(&fixture, &fixture).diagnose(&context);
    let diagnostic = format!("{result:?}");

    assert_eq!(result.outcome(), DoctorOutcome::Fail);
    assert!(!diagnostic.contains("fictional-sensitive-path"));
}

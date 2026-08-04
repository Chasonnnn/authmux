use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use authmux::{
    AuthenticationContext, AwsLocalMetadataAdapter, EvidenceLevel, ExecutionSelection,
    IdentityMatch, ObservationReason, ProbeOutput, ProbePolicy, ProbeRunner, ProviderFailure,
    ReauthenticationNeed, SessionUsability, StatusEngine,
};

struct LocalMetadataFixture {
    sso_output: ProbeOutput,
    login_output: ProbeOutput,
    login_was_probed: Arc<AtomicBool>,
}

impl ProbeRunner for LocalMetadataFixture {
    fn probe(
        &self,
        command: &authmux::CommandSpec,
        selection: &ExecutionSelection,
        policy: ProbePolicy,
    ) -> Result<ProbeOutput, ProviderFailure> {
        assert_eq!(command.program(), "aws");
        assert!(selection.environment().is_empty());
        assert_eq!(policy.timeout(), Duration::from_secs(2));
        assert_eq!(policy.output_limit(), 4_096);
        let arguments = command
            .arguments()
            .iter()
            .map(|argument| argument.to_str().expect("fixture arguments are UTF-8"))
            .collect::<Vec<_>>();
        match arguments.as_slice() {
            [
                "configure",
                "get",
                "sso_account_id",
                "--profile",
                "crm-development",
            ] => Ok(self.sso_output.clone()),
            [
                "configure",
                "get",
                "login_session",
                "--profile",
                "crm-development",
            ] => {
                self.login_was_probed.store(true, Ordering::SeqCst);
                Ok(self.login_output.clone())
            }
            arguments => panic!("unexpected AWS local metadata command: {arguments:?}"),
        }
    }
}

fn fixture(sso_output: ProbeOutput, login_output: ProbeOutput) -> LocalMetadataFixture {
    LocalMetadataFixture {
        sso_output,
        login_output,
        login_was_probed: Arc::new(AtomicBool::new(false)),
    }
}

#[test]
fn configured_account_is_local_metadata_with_indeterminate_usability() {
    let fixture = fixture(
        ProbeOutput::exited(0, b"111111111111\n", b""),
        ProbeOutput::exited(1, b"", b"unused"),
    );
    let login_was_probed = Arc::clone(&fixture.login_was_probed);
    let adapter = AwsLocalMetadataAdapter::new(fixture);
    let engine = StatusEngine::new(adapter);
    let context = AuthenticationContext::aws("crm", "crm-development", "111111111111")
        .expect("fictional context is valid");

    let observation = engine
        .observe(&context)
        .expect("local metadata observation succeeds");

    assert_eq!(
        observation
            .observed_identity()
            .expect("configured account is present")
            .account(),
        "111111111111"
    );
    assert_eq!(observation.identity_match(), IdentityMatch::Match);
    assert_eq!(observation.usability(), SessionUsability::Indeterminate);
    assert_eq!(
        observation.reason(),
        Some(ObservationReason::InsufficientEvidence)
    );
    assert_eq!(
        observation.reauthentication_need(),
        ReauthenticationNeed::Unknown
    );
    assert_eq!(observation.evidence_level(), EvidenceLevel::LocalMetadata);
    assert!(
        !login_was_probed.load(Ordering::SeqCst),
        "a usable sso_account_id must avoid the fallback probe"
    );
}

#[test]
fn aws_login_session_account_is_local_metadata_with_indeterminate_usability() {
    let adapter = AwsLocalMetadataAdapter::new(fixture(
        ProbeOutput::exited(1, b"", b"fictional setting not found"),
        ProbeOutput::exited(
            0,
            b"arn:aws:sts::111111111111:assumed-role/FictionalRole/fictional-user\n",
            b"",
        ),
    ));
    let engine = StatusEngine::new(adapter);
    let context = AuthenticationContext::aws("crm", "crm-development", "111111111111")
        .expect("fictional context is valid");

    let observation = engine
        .observe(&context)
        .expect("AWS login metadata observation succeeds");

    assert_eq!(
        observation
            .observed_identity()
            .expect("configured account is present")
            .account(),
        "111111111111"
    );
    assert_eq!(observation.identity_match(), IdentityMatch::Match);
    assert_eq!(observation.usability(), SessionUsability::Indeterminate);
    assert_eq!(
        observation.reason(),
        Some(ObservationReason::InsufficientEvidence)
    );
    assert_eq!(observation.evidence_level(), EvidenceLevel::LocalMetadata);
}

#[test]
fn absent_account_metadata_is_an_unverified_observation_not_a_command_failure() {
    let adapter = AwsLocalMetadataAdapter::new(fixture(
        ProbeOutput::exited(1, b"", b"fictional setting not found"),
        ProbeOutput::exited(1, b"", b"fictional setting not found"),
    ));
    let engine = StatusEngine::new(adapter);
    let context = AuthenticationContext::aws("crm", "crm-development", "111111111111")
        .expect("fictional context is valid");

    let observation = engine
        .observe(&context)
        .expect("missing local metadata remains report data");

    assert_eq!(observation.observed_identity(), None);
    assert_eq!(observation.identity_match(), IdentityMatch::Unverified);
    assert_eq!(observation.usability(), SessionUsability::Indeterminate);
    assert_eq!(
        observation.reason(),
        Some(ObservationReason::InsufficientEvidence)
    );
}

#[test]
fn configured_account_mismatch_does_not_claim_session_usability() {
    let adapter = AwsLocalMetadataAdapter::new(fixture(
        ProbeOutput::exited(0, b"222222222222\n", b""),
        ProbeOutput::exited(1, b"", b"unused"),
    ));
    let engine = StatusEngine::new(adapter);
    let context = AuthenticationContext::aws("crm", "crm-development", "111111111111")
        .expect("fictional context is valid");

    let observation = engine
        .observe(&context)
        .expect("local metadata observation succeeds");

    assert_eq!(observation.identity_match(), IdentityMatch::Mismatch);
    assert_eq!(observation.usability(), SessionUsability::Indeterminate);
    assert_eq!(observation.evidence_level(), EvidenceLevel::LocalMetadata);
}

#[test]
fn malformed_local_metadata_becomes_sanitized_provider_error_data() {
    let seeded_output = b"111111111111 unexpected-sensitive-metadata\n";
    let adapter = AwsLocalMetadataAdapter::new(fixture(
        ProbeOutput::exited(0, seeded_output, b""),
        ProbeOutput::exited(1, b"", b"unused"),
    ));
    let engine = StatusEngine::new(adapter);
    let context = AuthenticationContext::aws("crm", "crm-development", "111111111111")
        .expect("fictional context is valid");

    let observation = engine
        .observe(&context)
        .expect("malformed local metadata remains sanitized report data");

    assert_eq!(observation.observed_identity(), None);
    assert_eq!(observation.identity_match(), IdentityMatch::Unverified);
    assert_eq!(observation.reason(), Some(ObservationReason::ProviderError));
}

#[test]
fn malformed_aws_login_session_is_sanitized_provider_error_data() {
    let seeded_output =
        b"arn:aws:sts::111111111111:assumed-role/FictionalRole/sensitive-principal extra\n";
    let adapter = AwsLocalMetadataAdapter::new(fixture(
        ProbeOutput::exited(1, b"", b"fictional setting not found"),
        ProbeOutput::exited(0, seeded_output, b""),
    ));
    let engine = StatusEngine::new(adapter);
    let context = AuthenticationContext::aws("crm", "crm-development", "111111111111")
        .expect("fictional context is valid");

    let observation = engine
        .observe(&context)
        .expect("malformed AWS login metadata remains sanitized report data");

    assert_eq!(observation.observed_identity(), None);
    assert_eq!(observation.identity_match(), IdentityMatch::Unverified);
    assert_eq!(observation.reason(), Some(ObservationReason::ProviderError));
}

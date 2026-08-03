use std::time::Duration;

use authmux::{
    AuthenticationContext, AwsLocalMetadataAdapter, EvidenceLevel, ExecutionSelection,
    IdentityMatch, ObservationReason, ProbeOutput, ProbePolicy, ProbeRunner, ProviderFailure,
    ReauthenticationNeed, SessionUsability, StatusEngine,
};

struct LocalMetadataFixture {
    output: ProbeOutput,
}

impl ProbeRunner for LocalMetadataFixture {
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
                "configure",
                "get",
                "sso_account_id",
                "--profile",
                "crm-development",
            ]
        );
        assert!(selection.environment().is_empty());
        assert_eq!(policy.timeout(), Duration::from_secs(2));
        assert_eq!(policy.output_limit(), 4_096);
        Ok(self.output.clone())
    }
}

#[test]
fn configured_account_is_local_metadata_with_indeterminate_usability() {
    let adapter = AwsLocalMetadataAdapter::new(LocalMetadataFixture {
        output: ProbeOutput::exited(0, b"111111111111\n", b""),
    });
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
}

#[test]
fn absent_account_metadata_is_an_unverified_observation_not_a_command_failure() {
    let adapter = AwsLocalMetadataAdapter::new(LocalMetadataFixture {
        output: ProbeOutput::exited(1, b"", b"fictional setting not found"),
    });
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
    let adapter = AwsLocalMetadataAdapter::new(LocalMetadataFixture {
        output: ProbeOutput::exited(0, b"222222222222\n", b""),
    });
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
    let adapter = AwsLocalMetadataAdapter::new(LocalMetadataFixture {
        output: ProbeOutput::exited(0, seeded_output, b""),
    });
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

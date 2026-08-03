use authmux::{
    AuthenticationContext, EvidenceLevel, IdentityMatch, ObservationReason, ObservedIdentity,
    ProviderFailure, ReauthenticationNeed, SessionUsability, StatusAdapter, StatusEngine,
    StatusObservation,
};

struct FixedStatusAdapter {
    observation: StatusObservation,
}

impl StatusAdapter for FixedStatusAdapter {
    fn observe_status(
        &self,
        _context: &AuthenticationContext,
    ) -> Result<StatusObservation, ProviderFailure> {
        Ok(self.observation.clone())
    }
}

#[test]
fn every_status_axis_value_survives_core_normalization_independently() {
    let reasons = [
        ObservationReason::Expired,
        ObservationReason::Missing,
        ObservationReason::Unreachable,
        ObservationReason::ProviderError,
        ObservationReason::InsufficientEvidence,
    ];
    let reauthentication_needs = [
        ReauthenticationNeed::Required,
        ReauthenticationNeed::NotRequired,
        ReauthenticationNeed::Unknown,
        ReauthenticationNeed::NotApplicable,
    ];
    let evidence_levels = [
        EvidenceLevel::LocalMetadata,
        EvidenceLevel::ProviderValidation,
        EvidenceLevel::ConnectivityOnly,
    ];
    let context = AuthenticationContext::aws("crm", "crm-development", "111111111111")
        .expect("fictional context is valid");

    for reason in reasons {
        for reauthentication_need in reauthentication_needs {
            for evidence_level in evidence_levels {
                let observed_identity = ObservedIdentity::aws_account("111111111111")
                    .expect("fictional identity is valid");
                let engine = StatusEngine::new(FixedStatusAdapter {
                    observation: StatusObservation::indeterminate(
                        observed_identity,
                        reason,
                        reauthentication_need,
                        evidence_level,
                    ),
                });

                let observation = engine
                    .observe(&context)
                    .expect("fixed observation normalizes");

                assert_eq!(observation.identity_match(), IdentityMatch::Match);
                assert_eq!(observation.usability(), SessionUsability::Indeterminate);
                assert_eq!(observation.reason(), Some(reason));
                assert_eq!(observation.reauthentication_need(), reauthentication_need);
                assert_eq!(observation.evidence_level(), evidence_level);
            }
        }
    }
}

#[test]
fn usable_unusable_and_indeterminate_remain_distinct() {
    let identity =
        || ObservedIdentity::aws_account("111111111111").expect("fictional identity is valid");
    let observations = [
        (
            StatusObservation::usable_provider_validation(identity()),
            SessionUsability::Usable,
        ),
        (
            StatusObservation::unusable(
                identity(),
                ObservationReason::Expired,
                ReauthenticationNeed::Required,
                EvidenceLevel::ProviderValidation,
            ),
            SessionUsability::Unusable,
        ),
        (
            StatusObservation::indeterminate(
                identity(),
                ObservationReason::Unreachable,
                ReauthenticationNeed::Unknown,
                EvidenceLevel::ConnectivityOnly,
            ),
            SessionUsability::Indeterminate,
        ),
    ];

    for (observation, expected_usability) in observations {
        assert_eq!(observation.usability(), expected_usability);
    }
}

#[test]
fn missing_observed_identity_stays_unverified() {
    let context = AuthenticationContext::aws("crm", "crm-development", "111111111111")
        .expect("fictional context is valid");
    let engine = StatusEngine::new(FixedStatusAdapter {
        observation: StatusObservation::indeterminate_without_identity(
            ObservationReason::InsufficientEvidence,
            ReauthenticationNeed::Unknown,
            EvidenceLevel::LocalMetadata,
        ),
    });

    let observation = engine
        .observe(&context)
        .expect("identity-free observation normalizes");

    assert_eq!(observation.observed_identity(), None);
    assert_eq!(observation.identity_match(), IdentityMatch::Unverified);
}

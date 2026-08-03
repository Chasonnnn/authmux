use std::cell::Cell;
use std::rc::Rc;

use authmux::{
    AuthenticationContext, CommandSpec, ContextEngine, EvidenceLevel, ExecutionContextResolver,
    ExecutionFailure, ExecutionOutcome, ExecutionSelection, ObservationReason, ObservedIdentity,
    ProcessRunner, ProviderAdapter, ProviderFailure, ReauthenticationNeed, StatusObservation,
};

struct FixedAwsAdapter {
    observed_account: String,
}

struct ExpiredAwsAdapter;

impl ProviderAdapter for ExpiredAwsAdapter {
    fn observe(
        &self,
        _context: &AuthenticationContext,
    ) -> Result<StatusObservation, ProviderFailure> {
        Ok(StatusObservation::unusable(
            ObservedIdentity::aws_account("111111111111")?,
            ObservationReason::Expired,
            ReauthenticationNeed::Required,
            EvidenceLevel::ProviderValidation,
        ))
    }

    fn execution_selection(
        &self,
        context: &AuthenticationContext,
    ) -> Result<ExecutionSelection, ProviderFailure> {
        Ok(ExecutionSelection::aws_profile(context.provider_profile()))
    }
}

struct IndeterminateAwsAdapter;

impl ProviderAdapter for IndeterminateAwsAdapter {
    fn observe(
        &self,
        _context: &AuthenticationContext,
    ) -> Result<StatusObservation, ProviderFailure> {
        Ok(StatusObservation::indeterminate(
            ObservedIdentity::aws_account("111111111111")?,
            ObservationReason::InsufficientEvidence,
            ReauthenticationNeed::Unknown,
            EvidenceLevel::LocalMetadata,
        ))
    }

    fn execution_selection(
        &self,
        context: &AuthenticationContext,
    ) -> Result<ExecutionSelection, ProviderFailure> {
        Ok(ExecutionSelection::aws_profile(context.provider_profile()))
    }
}

impl ProviderAdapter for FixedAwsAdapter {
    fn observe(
        &self,
        _context: &AuthenticationContext,
    ) -> Result<StatusObservation, ProviderFailure> {
        Ok(StatusObservation::usable_provider_validation(
            ObservedIdentity::aws_account(&self.observed_account)?,
        ))
    }

    fn execution_selection(
        &self,
        context: &AuthenticationContext,
    ) -> Result<ExecutionSelection, ProviderFailure> {
        Ok(ExecutionSelection::aws_profile(context.provider_profile()))
    }
}

struct RecordingRunner {
    called: Rc<Cell<bool>>,
}

struct FixedContextResolver {
    context: AuthenticationContext,
}

impl ExecutionContextResolver for FixedContextResolver {
    fn resolve_current(&self) -> Result<AuthenticationContext, ExecutionFailure> {
        Ok(self.context.clone())
    }
}

impl ProcessRunner for RecordingRunner {
    fn run(
        &self,
        _command: &CommandSpec,
        _selection: &ExecutionSelection,
    ) -> Result<ExecutionOutcome, ExecutionFailure> {
        self.called.set(true);
        Ok(ExecutionOutcome::exited(0))
    }
}

#[test]
fn mismatched_observed_identity_refuses_child_execution() {
    let runner_called = Rc::new(Cell::new(false));
    let engine = ContextEngine::new(
        FixedAwsAdapter {
            observed_account: "222222222222".to_owned(),
        },
        RecordingRunner {
            called: Rc::clone(&runner_called),
        },
    );
    let context = AuthenticationContext::aws("crm", "crm-development", "111111111111")
        .expect("fictional context is valid");
    let command = CommandSpec::new("aws", ["s3", "ls"]).expect("command is valid");
    let resolver = FixedContextResolver {
        context: context.clone(),
    };

    let failure = engine
        .execute(&context, &command, &resolver)
        .expect_err("identity mismatch must fail closed");

    assert_eq!(
        failure,
        ExecutionFailure::IdentityMismatch {
            expected: "111111111111".to_owned(),
            observed: "222222222222".to_owned(),
        }
    );
    assert!(!runner_called.get(), "the child command must not run");
}

#[test]
fn unusable_matching_session_refuses_child_execution() {
    let runner_called = Rc::new(Cell::new(false));
    let engine = ContextEngine::new(
        ExpiredAwsAdapter,
        RecordingRunner {
            called: Rc::clone(&runner_called),
        },
    );
    let context = AuthenticationContext::aws("crm", "crm-development", "111111111111")
        .expect("fictional context is valid");
    let command = CommandSpec::new("aws", ["s3", "ls"]).expect("command is valid");
    let resolver = FixedContextResolver {
        context: context.clone(),
    };

    let failure = engine
        .execute(&context, &command, &resolver)
        .expect_err("an unusable session must fail closed");

    assert_eq!(
        failure,
        ExecutionFailure::SessionUnusable {
            reason: ObservationReason::Expired,
            reauthentication_need: ReauthenticationNeed::Required,
        }
    );
    assert!(!runner_called.get(), "the child command must not run");
}

#[test]
fn indeterminate_session_refuses_child_execution() {
    let runner_called = Rc::new(Cell::new(false));
    let engine = ContextEngine::new(
        IndeterminateAwsAdapter,
        RecordingRunner {
            called: Rc::clone(&runner_called),
        },
    );
    let context = AuthenticationContext::aws("crm", "crm-development", "111111111111")
        .expect("fictional context is valid");
    let command = CommandSpec::new("aws", ["s3", "ls"]).expect("command is valid");
    let resolver = FixedContextResolver {
        context: context.clone(),
    };

    let failure = engine
        .execute(&context, &command, &resolver)
        .expect_err("indeterminate usability must fail closed");

    assert_eq!(
        failure,
        ExecutionFailure::SessionIndeterminate {
            reason: ObservationReason::InsufficientEvidence,
        }
    );
    assert!(!runner_called.get(), "the child command must not run");
}

#[test]
fn changed_context_after_provider_validation_refuses_child_execution() {
    let runner_called = Rc::new(Cell::new(false));
    let engine = ContextEngine::new(
        FixedAwsAdapter {
            observed_account: "111111111111".to_owned(),
        },
        RecordingRunner {
            called: Rc::clone(&runner_called),
        },
    );
    let context = AuthenticationContext::aws("crm", "crm-development", "111111111111")
        .expect("fictional context is valid");
    let changed_context = AuthenticationContext::aws("crm", "crm-production", "222222222222")
        .expect("fictional changed context is valid");
    let command = CommandSpec::new("aws", ["s3", "ls"]).expect("command is valid");
    let resolver = FixedContextResolver {
        context: changed_context,
    };

    let failure = engine
        .execute(&context, &command, &resolver)
        .expect_err("a context changed after observation must fail closed");

    assert_eq!(failure, ExecutionFailure::ContextChanged);
    assert!(!runner_called.get(), "the child command must not run");
}

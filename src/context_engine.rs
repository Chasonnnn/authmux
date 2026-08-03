use crate::{
    AuthenticationContext, CommandSpec, ExecutionFailure, ExecutionOutcome, ExecutionSelection,
    IdentityMatch, ProviderFailure, SessionUsability, StatusObservation,
};

pub trait ProviderAdapter {
    /// Produces a read-only Status Observation for the selected profile.
    ///
    /// # Errors
    ///
    /// Returns a sanitized provider failure when observation cannot complete.
    fn observe(
        &self,
        context: &AuthenticationContext,
    ) -> Result<StatusObservation, ProviderFailure>;

    /// Produces process-scoped selectors without exposing Credentials.
    ///
    /// # Errors
    ///
    /// Returns a sanitized provider failure when safe selection is unsupported.
    fn execution_selection(
        &self,
        context: &AuthenticationContext,
    ) -> Result<ExecutionSelection, ProviderFailure>;
}

pub trait ProcessRunner {
    /// Runs a child with the selected environment and exact argument vector.
    ///
    /// # Errors
    ///
    /// Returns a sanitized execution failure when the child cannot be run.
    fn run(
        &self,
        command: &CommandSpec,
        selection: &ExecutionSelection,
    ) -> Result<ExecutionOutcome, ExecutionFailure>;
}

pub trait ExecutionContextResolver {
    /// Re-resolves the selected Authentication Context immediately before spawn.
    ///
    /// # Errors
    ///
    /// Returns a sanitized execution failure when current configuration cannot
    /// be resolved safely.
    fn resolve_current(&self) -> Result<AuthenticationContext, ExecutionFailure>;
}

pub trait StatusAdapter {
    /// Produces a read-only Status Observation without refreshing credentials.
    ///
    /// # Errors
    ///
    /// Returns a sanitized provider failure when the local observation cannot
    /// be performed safely.
    fn observe_status(
        &self,
        context: &AuthenticationContext,
    ) -> Result<StatusObservation, ProviderFailure>;
}

pub struct StatusEngine<A> {
    adapter: A,
}

impl<A> StatusEngine<A>
where
    A: StatusAdapter,
{
    #[must_use]
    pub fn new(adapter: A) -> Self {
        Self { adapter }
    }

    /// Observes local provider metadata and applies core identity comparison.
    ///
    /// # Errors
    ///
    /// Returns a sanitized provider failure when observation cannot run.
    pub fn observe(
        &self,
        context: &AuthenticationContext,
    ) -> Result<StatusObservation, ProviderFailure> {
        self.adapter
            .observe_status(context)
            .map(|observation| observation.compare_to(context.expected_account()))
    }
}

pub struct ContextEngine<A, R> {
    provider: A,
    runner: R,
}

impl<A, R> ContextEngine<A, R>
where
    A: ProviderAdapter,
    R: ProcessRunner,
{
    #[must_use]
    pub fn new(provider: A, runner: R) -> Self {
        Self { provider, runner }
    }

    /// Verifies identity and usability before running a child command.
    ///
    /// # Errors
    ///
    /// Fails closed on identity mismatch, unusable evidence, provider failure,
    /// or child execution failure.
    pub fn execute<C>(
        &self,
        context: &AuthenticationContext,
        command: &CommandSpec,
        resolver: &C,
    ) -> Result<ExecutionOutcome, ExecutionFailure>
    where
        C: ExecutionContextResolver,
    {
        let observation = self
            .provider
            .observe(context)?
            .compare_to(context.expected_account());

        if observation.identity_match() == IdentityMatch::Mismatch {
            let Some(observed_identity) = observation.observed_identity() else {
                return Err(ProviderFailure::sanitized(
                    "provider returned an inconsistent identity mismatch",
                )
                .into());
            };
            return Err(ExecutionFailure::IdentityMismatch {
                expected: context.expected_account().to_owned(),
                observed: observed_identity.account().to_owned(),
            });
        }

        if observation.usability() == SessionUsability::Unusable {
            let Some(reason) = observation.reason() else {
                return Err(ProviderFailure::sanitized(
                    "provider returned an inconsistent unusable observation",
                )
                .into());
            };
            return Err(ExecutionFailure::SessionUnusable {
                reason,
                reauthentication_need: observation.reauthentication_need(),
            });
        }

        if observation.usability() == SessionUsability::Indeterminate {
            let Some(reason) = observation.reason() else {
                return Err(ProviderFailure::sanitized(
                    "provider returned an inconsistent indeterminate observation",
                )
                .into());
            };
            return Err(ExecutionFailure::SessionIndeterminate { reason });
        }

        let current_context = resolver.resolve_current()?;
        if current_context != *context {
            return Err(ExecutionFailure::ContextChanged);
        }

        let selection = self.provider.execution_selection(&current_context)?;
        self.runner.run(command, &selection)
    }
}

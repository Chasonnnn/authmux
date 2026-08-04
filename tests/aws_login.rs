use std::collections::BTreeMap;

use authmux::{
    AwsLoginFailure, AwsLoginMode, AwsLoginPlan, AwsLoginPlanner, CommandSpec, ContextDefinition,
    ExecutionSelection, ProbeOutput, ProbePolicy, ProbeRunner, ProviderFailure, UserConfig,
};

#[derive(Default)]
struct MetadataFixture {
    values: BTreeMap<(String, String), ProbeOutput>,
    failure: Option<ProviderFailure>,
}

impl MetadataFixture {
    fn with(mut self, profile: &str, setting: &str, value: &str) -> Self {
        self.values.insert(
            (profile.to_owned(), setting.to_owned()),
            ProbeOutput::exited(0, value.as_bytes(), b""),
        );
        self
    }

    fn failing(message: &str) -> Self {
        Self {
            values: BTreeMap::new(),
            failure: Some(ProviderFailure::sanitized(message)),
        }
    }
}

impl ProbeRunner for MetadataFixture {
    fn probe(
        &self,
        command: &CommandSpec,
        _selection: &ExecutionSelection,
        _policy: ProbePolicy,
    ) -> Result<ProbeOutput, ProviderFailure> {
        if let Some(failure) = &self.failure {
            return Err(failure.clone());
        }
        let arguments = command
            .arguments()
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let [configure, get, setting, profile_flag, profile] = arguments.as_slice() else {
            return Err(ProviderFailure::sanitized("unexpected fictional command"));
        };
        if configure != "configure" || get != "get" || profile_flag != "--profile" {
            return Err(ProviderFailure::sanitized("unexpected fictional command"));
        }
        Ok(self
            .values
            .get(&(profile.clone(), setting.clone()))
            .cloned()
            .unwrap_or_else(|| ProbeOutput::exited(1, b"", b"fictional setting absent")))
    }
}

#[test]
fn mixed_native_login_modes_fail_closed_without_exposing_metadata() {
    let context = aws_context("mixed", "mixed-profile", "111111111111");
    let runner = MetadataFixture::default()
        .with(
            "mixed-profile",
            "login_session",
            "arn:aws:iam::111111111111:user/sensitive-principal",
        )
        .with("mixed-profile", "sso_account_id", "111111111111");

    let failure = AwsLoginPlanner::new(runner)
        .plan(context.aws().expect("AWS context exists"))
        .expect_err("ambiguous profile is rejected");

    assert_eq!(failure, AwsLoginFailure::AmbiguousProfile);
    let diagnostic = failure.to_string();
    assert!(!diagnostic.contains("sensitive-principal"));
    assert!(!diagnostic.contains("111111111111"));
}

#[test]
fn source_profile_cycle_is_rejected_before_native_login() {
    let context = aws_context("role", "role-a", "333333333333");
    let runner = MetadataFixture::default()
        .with(
            "role-a",
            "role_arn",
            "arn:aws:iam::333333333333:role/fictional-a",
        )
        .with("role-a", "source_profile", "role-b")
        .with(
            "role-b",
            "role_arn",
            "arn:aws:iam::222222222222:role/fictional-b",
        )
        .with("role-b", "source_profile", "role-a");

    let failure = AwsLoginPlanner::new(runner)
        .plan(context.aws().expect("AWS context exists"))
        .expect_err("cycle is rejected");

    assert_eq!(failure, AwsLoginFailure::SourceProfileCycle);
}

#[test]
fn selected_role_account_must_match_the_expected_identity() {
    let context = aws_context("role", "role-profile", "333333333333");
    let runner = MetadataFixture::default()
        .with(
            "role-profile",
            "role_arn",
            "arn:aws:iam::222222222222:role/fictional-role",
        )
        .with("role-profile", "source_profile", "source-console");

    let failure = AwsLoginPlanner::new(runner)
        .plan(context.aws().expect("AWS context exists"))
        .expect_err("target account mismatch is rejected");

    assert_eq!(failure, AwsLoginFailure::IdentityMismatch);
}

#[test]
fn provider_probe_failure_is_sanitized_by_the_login_interface() {
    let context = aws_context("console", "console-profile", "111111111111");
    let runner = MetadataFixture::failing("ghp_fictional_sensitive_provider_output");

    let failure = AwsLoginPlanner::new(runner)
        .plan(context.aws().expect("AWS context exists"))
        .expect_err("probe failure is rejected");

    assert_eq!(failure, AwsLoginFailure::MetadataProbeFailed);
    assert!(!failure.to_string().contains("ghp_fictional"));
}

#[test]
fn material_context_drift_is_rejected_but_description_drift_is_ignored() {
    let initial = aws_context("console", "console-profile", "111111111111");
    let description_only = UserConfig::parse(
        "version = 1\n\
         [contexts.console]\n\
         description = \"new label\"\n\
         [contexts.console.providers.aws]\n\
         profile = \"console-profile\"\n\
         expected_account = \"111111111111\"\n",
    )
    .expect("description-only config is valid")
    .resolve_context_definition("console")
    .expect("description-only context resolves");
    let changed = aws_context("console", "other-profile", "111111111111");

    assert_eq!(
        AwsLoginPlan::ensure_context_unchanged(&initial, &description_only),
        Ok(())
    );
    assert_eq!(
        AwsLoginPlan::ensure_context_unchanged(&initial, &changed),
        Err(AwsLoginFailure::ContextChanged)
    );
}

#[test]
fn role_source_can_use_identity_center_in_a_different_account() {
    let context = aws_context("role", "role-profile", "333333333333");
    let runner = MetadataFixture::default()
        .with(
            "role-profile",
            "role_arn",
            "arn:aws:iam::333333333333:role/fictional-role",
        )
        .with("role-profile", "source_profile", "source-sso")
        .with("source-sso", "sso_account_id", "222222222222");

    let plan = AwsLoginPlanner::new(runner)
        .plan(context.aws().expect("AWS context exists"))
        .expect("cross-account role source is supported");

    assert_eq!(plan.mode(), AwsLoginMode::IdentityCenter);
    assert_eq!(plan.login_profile(), "source-sso");
}

fn aws_context(name: &str, profile: &str, account: &str) -> ContextDefinition {
    UserConfig::parse(&format!(
        "version = 1\n\
         [contexts.{name}.providers.aws]\n\
         profile = \"{profile}\"\n\
         expected_account = \"{account}\"\n"
    ))
    .expect("fictional config is valid")
    .resolve_context_definition(name)
    .expect("fictional context resolves")
}

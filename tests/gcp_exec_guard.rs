#![cfg(unix)]

use std::fmt::Write as _;

use authmux::{GcpExecutionFailure, GcpExecutionGuard, UserConfig};

#[test]
fn final_guard_rejects_material_gcp_profile_drift() {
    let initial = definition("crm", "researcher@example.test", "fictional-project", false);
    for current in [
        definition("crm", "other@example.test", "fictional-project", false),
        definition("crm", "researcher@example.test", "other-project", false),
        definition(
            "other",
            "researcher@example.test",
            "fictional-project",
            false,
        ),
        definition("crm", "researcher@example.test", "fictional-project", true),
    ] {
        assert_eq!(
            GcpExecutionGuard::ensure_unchanged(&initial, &current),
            Err(GcpExecutionFailure::ContextChanged)
        );
    }
}

#[test]
fn final_guard_ignores_non_material_description_drift() {
    let initial = definition_with_description("before");
    let current = definition_with_description("after");

    GcpExecutionGuard::ensure_unchanged(&initial, &current)
        .expect("description changes do not alter execution selection");
}

fn definition(
    name: &str,
    expected_principal: &str,
    expected_project: &str,
    include_aws: bool,
) -> authmux::ContextDefinition {
    let mut source = format!(
        "version = 1\n\
         [contexts.{name}.providers.gcp.gcloud]\n\
         config_dir = \"/home/researcher/.config/gcloud\"\n\
         configuration = \"crm-research\"\n\
         expected_principal = \"{expected_principal}\"\n\
         expected_project = \"{expected_project}\"\n"
    );
    if include_aws {
        write!(
            source,
            "[contexts.{name}.providers.aws]\n\
             profile = \"crm-development\"\n\
             expected_account = \"111111111111\"\n"
        )
        .expect("writing to a String cannot fail");
    }
    UserConfig::parse(&source)
        .expect("fixture configuration is valid")
        .resolve_context_definition(name)
        .expect("fixture context resolves")
}

fn definition_with_description(description: &str) -> authmux::ContextDefinition {
    UserConfig::parse(&format!(
        "version = 1\n\
         [contexts.crm]\n\
         description = \"{description}\"\n\
         [contexts.crm.providers.gcp.gcloud]\n\
         config_dir = \"/home/researcher/.config/gcloud\"\n\
         configuration = \"crm-research\"\n\
         expected_principal = \"researcher@example.test\"\n"
    ))
    .expect("fixture configuration is valid")
    .resolve_context_definition("crm")
    .expect("fixture context resolves")
}

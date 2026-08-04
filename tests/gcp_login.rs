#![cfg(unix)]

use authmux::{GcpLoginFailure, GcpLoginPlan, UserConfig};

#[test]
fn final_login_guard_rejects_material_context_drift() {
    let initial = definition("crm", "researcher@example.invalid", false, "before");
    for current in [
        definition("crm", "other@example.invalid", false, "before"),
        definition("other", "researcher@example.invalid", false, "before"),
        definition("crm", "researcher@example.invalid", true, "before"),
    ] {
        assert_eq!(
            GcpLoginPlan::ensure_unchanged(&initial, &current),
            Err(GcpLoginFailure::ContextChanged)
        );
    }
}

#[test]
fn final_login_guard_ignores_non_material_description_drift() {
    let initial = definition("crm", "researcher@example.invalid", false, "before");
    let current = definition("crm", "researcher@example.invalid", false, "after");

    GcpLoginPlan::ensure_unchanged(&initial, &current)
        .expect("description changes do not change the native login plan");
}

fn definition(
    name: &str,
    expected_principal: &str,
    include_aws: bool,
    description: &str,
) -> authmux::ContextDefinition {
    let aws = if include_aws {
        format!(
            "[contexts.{name}.providers.aws]\n\
             profile = \"crm-development\"\n\
             expected_account = \"111111111111\"\n"
        )
    } else {
        String::new()
    };
    UserConfig::parse(&format!(
        "version = 1\n\
         [contexts.{name}]\n\
         description = \"{description}\"\n\
         [contexts.{name}.providers.gcp.gcloud]\n\
         config_dir = \"/home/researcher/.config/gcloud\"\n\
         configuration = \"crm-research\"\n\
         expected_principal = \"{expected_principal}\"\n\
         {aws}"
    ))
    .expect("fixture configuration is valid")
    .resolve_context_definition(name)
    .expect("fixture context resolves")
}

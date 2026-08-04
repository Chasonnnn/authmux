use std::ffi::{OsStr, OsString};

use authmux::UserConfig;

#[test]
fn gcp_execution_selection_contains_only_declared_plane_selectors() {
    let config = UserConfig::parse(
        "version = 1\n\
         [contexts.crm.providers.gcp.gcloud]\n\
         config_dir = \"/home/researcher/.config/gcloud\"\n\
         configuration = \"crm-research\"\n\
         expected_principal = \"researcher@example.test\"\n\
         [contexts.crm.providers.gcp.adc]\n\
         mode = \"credential_file\"\n\
         credential_file = \"/home/researcher/.config/gcloud/adc/crm.json\"\n\
         expected_principal = \"workload@example.test\"\n",
    )
    .expect("GCP configuration is valid");
    let definition = config
        .resolve_context_definition("crm")
        .expect("GCP context resolves");
    let selection = definition
        .gcp()
        .expect("GCP Provider Profile is available")
        .execution_selection();

    let expected = [
        ("CLOUDSDK_CONFIG", "/home/researcher/.config/gcloud"),
        ("CLOUDSDK_ACTIVE_CONFIG_NAME", "crm-research"),
        ("CLOUDSDK_CORE_DISABLE_PROMPTS", "1"),
        ("CLOUDSDK_CORE_DISABLE_FILE_LOGGING", "1"),
        ("CLOUDSDK_CORE_DISABLE_USAGE_REPORTING", "1"),
        ("CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK", "1"),
        (
            "GOOGLE_APPLICATION_CREDENTIALS",
            "/home/researcher/.config/gcloud/adc/crm.json",
        ),
    ]
    .map(|(name, value)| (OsString::from(name), OsString::from(value)));

    assert_eq!(selection.environment(), expected);
    assert!(
        selection
            .environment()
            .iter()
            .all(|(name, _)| name != OsStr::new("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES"))
    );
}

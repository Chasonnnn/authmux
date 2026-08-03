use authmux::UserConfig;

#[test]
fn secret_shaped_profile_value_is_rejected_without_echoing_it() {
    let seeded_secret = "AKIA1111111111111111";
    let source = format!(
        "version = 1\n\
         [contexts.crm.providers.aws]\n\
         profile = \"{seeded_secret}\"\n\
         expected_account = \"111111111111\"\n"
    );

    let failure = UserConfig::parse(&source).expect_err("secret-shaped values must be rejected");
    let diagnostic = failure.to_string();

    assert_eq!(
        diagnostic,
        "user configuration contains a secret-shaped value where a provider profile was expected"
    );
    assert!(!diagnostic.contains(seeded_secret));
}

#[test]
fn display_description_does_not_change_context_resolution() {
    let source = "version = 1\n\
                  [contexts.crm]\n\
                  description = \"Fictional CRM project\"\n\
                  [contexts.crm.providers.aws]\n\
                  profile = \"crm-development\"\n\
                  expected_account = \"111111111111\"\n";

    let config = UserConfig::parse(source).expect("documented display metadata is valid");
    let context = config
        .resolve_context("crm")
        .expect("fictional context resolves");

    assert_eq!(context.name(), "crm");
    assert_eq!(context.provider_profile(), "crm-development");
    assert_eq!(context.expected_account(), "111111111111");
}

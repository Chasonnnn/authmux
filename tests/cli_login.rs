#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn ssh_login_previews_the_target_and_delegates_to_openssh() {
    let fixture = LoginFixture::new("ssh-success");
    let (bin_directory, _control_master) = fixture.configure_ssh_with_transport(0, 0, true);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "empire", "--provider", "ssh"])
        .env("HOME", fixture.path.join("home"))
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .env("GH_TOKEN", "ghp_fictional_must_not_pass")
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(
        stdout,
        "login: empire\n\
         provider: ssh\n\
         host alias: empire-alpha\n\
         expected remote principal: researcher@example.invalid\n\
         native command: ssh empire-alpha\n\
         native argv: empire-alpha\n\
         inherited GH_TOKEN: absent\n\
         result: native login command exited successfully; remote session usability remains unverified\n\
         post-login transport reuse: active\n"
    );
    assert!(stderr.is_empty());
}

#[test]
fn ssh_login_can_print_an_external_terminal_handoff_without_starting_native_login() {
    let fixture = LoginFixture::new("ssh-print-command");
    let bin_directory = fixture.configure_ssh(0);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "empire", "--provider", "ssh", "--print-command"])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(
        stdout,
        "login: empire\n\
         provider: ssh\n\
         host alias: empire-alpha\n\
         expected remote principal: researcher@example.invalid\n\
         native command: ssh empire-alpha\n\
         handoff: rerun this authmux login in an external terminal without --print-command; authmux did not start the native command\n"
    );
    assert!(stderr.is_empty());
    assert!(
        !fixture.path.join("ssh-ran").exists(),
        "the external-terminal handoff must not start the native login command"
    );
}

#[test]
fn successful_ssh_login_reports_an_inactive_controlmaster_without_claiming_failure() {
    let fixture = LoginFixture::new("ssh-success-inactive");
    let (bin_directory, _control_master) = fixture.configure_ssh_with_transport(0, 97, false);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "empire", "--provider", "ssh"])
        .env("HOME", fixture.path.join("home"))
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(stdout.contains(
        "result: native login command exited successfully; remote session usability remains unverified\n"
    ));
    assert!(stdout.ends_with("post-login transport reuse: inactive\n"));
    assert!(stderr.is_empty());
    assert!(
        !fixture.path.join("ssh-status-ran").exists(),
        "an absent socket must not start an SSH control probe"
    );
}

#[test]
fn gcp_login_previews_selected_account_and_delegates_to_gcloud() {
    let fixture = LoginFixture::new("gcp-success");
    let bin_directory = fixture.configure_gcp(0);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "crm", "--provider", "gcp"])
        .env("HOME", fixture.path.join("home"))
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .env(
            "GOOGLE_APPLICATION_CREDENTIALS",
            "/ambient/credential-that-must-not-pass.json",
        )
        .env("CLOUDSDK_CORE_DISABLE_PROMPTS", "1")
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(
        stdout,
        format!(
            "login: crm\n\
             provider: gcp\n\
             credential plane: gcloud_cli\n\
             gcloud configuration: crm-research\n\
             expected gcloud identity: researcher@example.invalid\n\
             login account: researcher@example.invalid\n\
             native command: gcloud auth login researcher@example.invalid --brief --force\n\
             native argv: auth|login|researcher@example.invalid|--brief|--force\n\
             CLOUDSDK_CONFIG={}\n\
             CLOUDSDK_ACTIVE_CONFIG_NAME=crm-research\n\
             CLOUDSDK_CORE_DISABLE_PROMPTS=absent\n\
             CLOUDSDK_CORE_DISABLE_FILE_LOGGING=1\n\
             CLOUDSDK_CORE_DISABLE_USAGE_REPORTING=1\n\
             CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK=1\n\
             GOOGLE_APPLICATION_CREDENTIALS=absent\n\
             result: native GCP login command exited successfully; live session usability remains unverified\n",
            fixture.path.join("home/.config/gcloud").display()
        )
    );
    assert!(stderr.is_empty());
}

#[test]
fn gcp_login_can_print_an_external_terminal_handoff_without_starting_native_login() {
    let fixture = LoginFixture::new("gcp-print-command");
    let bin_directory = fixture.configure_gcp(0);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "crm", "--print-command", "--provider", "gcp"])
        .env("HOME", fixture.path.join("home"))
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .env(
            "GOOGLE_APPLICATION_CREDENTIALS",
            "/ambient/credential-that-must-not-pass.json",
        )
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(stdout.starts_with(
        "login: crm\n\
         provider: gcp\n\
         credential plane: gcloud_cli\n\
         gcloud configuration: crm-research\n\
         expected gcloud identity: researcher@example.invalid\n\
         login account: researcher@example.invalid\n\
         native command: gcloud auth login researcher@example.invalid --brief --force\n"
    ));
    assert!(stdout.ends_with(
        "handoff: rerun this authmux login in an external terminal without --print-command; authmux did not start the native command\n"
    ));
    assert!(stderr.is_empty());
    assert!(
        !fixture.path.join("gcloud-ran").exists(),
        "the external-terminal handoff must not start the native login command"
    );
}

#[test]
fn aws_console_login_previews_the_selected_profile_and_delegates_to_aws() {
    let fixture = LoginFixture::new("aws-console-success");
    let bin_directory = fixture.configure_aws_console(0);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "aws-console", "--provider", "aws"])
        .env("HOME", fixture.path.join("home"))
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .env("AWS_PROFILE", "ambient-profile-must-not-pass")
        .env("AWS_ACCESS_KEY_ID", "AKIAFICTIONALMUSTNOTPASS")
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(
        stdout,
        "login: aws-console\n\
         provider: aws\n\
         AWS Provider Profile: cornell-development\n\
         expected AWS account: 111111111111\n\
         reauthentication mode: console_login\n\
         native login profile: cornell-development\n\
         native command: aws login --profile cornell-development --no-cli-auto-prompt\n\
         native argv: login|--profile|cornell-development|--no-cli-auto-prompt\n\
         AWS_PROFILE=cornell-development\n\
         inherited AWS_ACCESS_KEY_ID: absent\n\
         result: native AWS login command exited successfully; live session usability remains unverified\n"
    );
    assert!(stderr.is_empty());
}

#[test]
fn aws_login_can_print_an_external_terminal_handoff_without_starting_native_login() {
    let fixture = LoginFixture::new("aws-console-print-command");
    let bin_directory = fixture.configure_aws_console(0);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args([
            "login",
            "aws-console",
            "--provider",
            "aws",
            "--print-command",
        ])
        .env("HOME", fixture.path.join("home"))
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .env("AWS_ACCESS_KEY_ID", "AKIAFICTIONALMUSTNOTPASS")
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(
        stdout,
        "login: aws-console\n\
         provider: aws\n\
         AWS Provider Profile: cornell-development\n\
         expected AWS account: 111111111111\n\
         reauthentication mode: console_login\n\
         native login profile: cornell-development\n\
         native command: aws login --profile cornell-development --no-cli-auto-prompt\n\
         handoff: rerun this authmux login in an external terminal without --print-command; authmux did not start the native command\n"
    );
    assert!(stderr.is_empty());
    assert!(
        !fixture.path.join("aws-login-ran").exists(),
        "the external-terminal handoff must not start the native login command"
    );
}

#[test]
fn aws_identity_center_login_uses_the_selected_sso_profile() {
    let fixture = LoginFixture::new("aws-sso-success");
    let bin_directory = fixture.configure_aws_sso(0);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "aws-sso", "--provider", "aws"])
        .env("HOME", fixture.path.join("home"))
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(stdout.contains("reauthentication mode: iam_identity_center\n"));
    assert!(stdout.contains("native login profile: research-sso\n"));
    assert!(
        stdout.contains(
            "native command: aws sso login --profile research-sso --no-cli-auto-prompt\n"
        )
    );
    assert!(
        stdout.contains("native argv: sso|login|--profile|research-sso|--no-cli-auto-prompt\n")
    );
    assert!(stderr.is_empty());
}

#[test]
fn aws_role_login_reauthenticates_its_declared_source_profile() {
    let fixture = LoginFixture::new("aws-role-source");
    let bin_directory = fixture.configure_aws_role_source(0);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "aws-role", "--provider", "aws"])
        .env("HOME", fixture.path.join("home"))
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(stdout.contains("AWS Provider Profile: workload-operator\n"));
    assert!(stdout.contains("expected AWS account: 333333333333\n"));
    assert!(stdout.contains("reauthentication mode: console_login\n"));
    assert!(stdout.contains("native login profile: source-console\n"));
    assert!(
        stdout
            .contains("native command: aws login --profile source-console --no-cli-auto-prompt\n")
    );
    assert!(stderr.is_empty());
}

#[test]
fn aws_login_preserves_native_failure_without_claiming_success() {
    let fixture = LoginFixture::new("aws-native-failure");
    let bin_directory = fixture.configure_aws_console(42);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "aws-console"])
        .env("HOME", fixture.path.join("home"))
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    assert_eq!(output.status.code(), Some(42));
    assert!(stdout.starts_with("login: aws-console\nprovider: aws\n"));
    assert!(!stdout.contains("exited successfully"));
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr is UTF-8"),
        "native AWS login command exited with status 42\n"
    );
}

#[test]
fn single_provider_gcp_login_does_not_require_a_provider_flag() {
    let fixture = LoginFixture::new("gcp-implicit-provider");
    let bin_directory = fixture.configure_gcp(0);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "crm"])
        .env("HOME", fixture.path.join("home"))
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(
        String::from_utf8(output.stdout)
            .expect("stdout is UTF-8")
            .starts_with("login: crm\nprovider: gcp\n")
    );
}

#[test]
fn impersonated_gcp_login_authenticates_the_declared_source_account() {
    let fixture = LoginFixture::new("gcp-impersonation");
    let bin_directory = fixture.configure_impersonated_gcp(0);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "crm", "--provider", "gcp"])
        .env("HOME", fixture.path.join("home"))
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(stdout.contains("expected gcloud identity: workload@example.invalid\n"));
    assert!(stdout.contains("login account: researcher@example.invalid\n"));
    assert!(
        stdout.contains("native argv: auth|login|researcher@example.invalid|--brief|--force\n")
    );
}

#[test]
fn adc_only_context_refuses_gcloud_login_before_native_spawn() {
    let fixture = LoginFixture::new("gcp-adc-only");
    let bin_directory = fixture.configure_adc_only_gcp();

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "crm", "--provider", "gcp"])
        .env("HOME", fixture.path.join("home"))
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr is UTF-8"),
        "refusing GCP login: the context does not declare a gcloud CLI credential plane\n"
    );
    assert!(!fixture.path.join("gcloud-ran").exists());
}

#[test]
fn gcp_login_preserves_native_failure_without_claiming_success() {
    let fixture = LoginFixture::new("gcp-native-failure");
    let bin_directory = fixture.configure_gcp(42);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "crm", "--provider", "gcp"])
        .env("HOME", fixture.path.join("home"))
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    assert_eq!(output.status.code(), Some(42));
    assert!(stdout.starts_with("login: crm\nprovider: gcp\n"));
    assert!(!stdout.contains("exited successfully"));
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr is UTF-8"),
        "native GCP login command exited with status 42\n"
    );
}

#[test]
fn gcp_login_reports_a_missing_native_executable_without_provider_output() {
    let fixture = LoginFixture::new("gcp-missing-executable");
    fixture.configure_gcp(0);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "crm", "--provider", "gcp"])
        .env("HOME", fixture.path.join("home"))
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", fixture.path.join("missing-bin"))
        .output()
        .expect("authmux runs");

    assert_eq!(output.status.code(), Some(126));
    assert!(
        String::from_utf8(output.stdout)
            .expect("stdout is UTF-8")
            .starts_with("login: crm\nprovider: gcp\n")
    );
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr is UTF-8"),
        "child execution failed: could not start child process (entity not found)\n"
    );
    assert!(!fixture.path.join("gcloud-ran").exists());
}

#[test]
fn gcp_login_preserves_native_termination_signal() {
    let fixture = LoginFixture::new("gcp-signal");
    let bin_directory = fixture.configure_signaling_gcp();

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "crm", "--provider", "gcp"])
        .env("HOME", fixture.path.join("home"))
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&output.status),
        Some(15)
    );
    assert!(output.stderr.is_empty());
    assert!(
        !String::from_utf8(output.stdout)
            .expect("stdout is UTF-8")
            .contains("exited successfully")
    );
}

#[test]
fn ssh_login_returns_the_native_failure_without_claiming_authentication() {
    let fixture = LoginFixture::new("ssh-failure");
    let bin_directory = fixture.configure_ssh(42);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "empire", "--provider", "ssh"])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(42), "stderr: {stderr}");
    assert!(stdout.starts_with("login: empire\nprovider: ssh\n"));
    assert!(!stdout.contains("exited successfully"));
    assert_eq!(stderr, "native SSH login command exited with status 42\n");
}

#[test]
fn mixed_context_login_requires_an_explicit_provider_before_spawn() {
    let fixture = LoginFixture::new("mixed-ambiguous");
    let bin_directory = fixture.configure_mixed();

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "mixed"])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert_eq!(
        stderr,
        "login requires --provider when the authentication context defines multiple providers\n"
    );
    assert!(!fixture.path.join("ssh-ran").exists());
}

#[test]
fn login_shortcuts_select_mapped_contexts_from_nested_directories() {
    for (shortcut, provider, context) in [
        ("aws", "aws", "aws-console"),
        ("gcloud", "gcp", "crm"),
        ("empireai", "ssh", "empire"),
    ] {
        let fixture = LoginFixture::new("shortcut");
        let bin_directory = match provider {
            "aws" => fixture.configure_aws_console(0),
            "gcp" => fixture.configure_gcp(0),
            _ => fixture.configure_ssh(0),
        };
        fixture.write_binding(&format!(
            "version = 1\n[project]\ncontext = \"unused\"\n[project.providers]\n{provider} = \"{context}\"\n"
        ));
        let nested = fixture.path.join("nested");
        fs::create_dir(&nested).unwrap();
        let output = fixture
            .command(&bin_directory)
            .current_dir(nested)
            .args([shortcut, "--print-command"])
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{shortcut}: {:?}",
            output.stderr
        );
        assert!(stdout.starts_with(&format!("login: {context}\nprovider: {provider}\n")));
        assert!(stdout.contains("authmux did not start the native command"));
        for marker in ["aws-login-ran", "gcloud-ran", "ssh-ran"] {
            assert!(!fixture.path.join(marker).exists());
        }
    }
}

#[test]
fn shortcut_uses_default_binding_and_preserves_native_exit_and_environment() {
    let fixture = LoginFixture::new("shortcut-default");
    let bin_directory = fixture.configure_ssh(23);
    fixture.write_binding("version = 1\n[project]\ncontext = \"empire\"\n");
    let output = fixture
        .command(&bin_directory)
        .args(["empireai"])
        .env("GH_TOKEN", "ghp_fictional_must_not_pass")
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(23));
    assert!(stdout.contains("native argv: empire-alpha\n"));
    assert!(stdout.contains("inherited GH_TOKEN: absent\n"));
    assert!(!stdout.contains("ghp_"));
}

#[test]
fn shortcut_explicit_context_overrides_mapping_and_works_outside_a_repository() {
    let fixture = LoginFixture::new("shortcut-explicit");
    let bin_directory = fixture.configure_ssh(0);
    for bound in [false, true] {
        if bound {
            fixture.write_binding("version = 1\n[project]\ncontext = \"unused\"\n[project.providers]\nssh = \"missing\"\n");
        }
        let output = fixture
            .command(&bin_directory)
            .args(["empireai", "--print-command", "--context", "empire"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .starts_with("login: empire\n")
        );
    }
    assert!(!fixture.path.join("ssh-ran").exists());
}

#[test]
fn shortcut_invalid_mapping_never_falls_back_to_default_context() {
    let fixture = LoginFixture::new("shortcut-invalid");
    let bin_directory = fixture.configure_mixed();
    for (binding, diagnostic) in [
        (
            "version = 1\n[project]\ncontext = \"mixed\"\n[project.providers]\nssh = \"missing\"\n",
            "context is not defined",
        ),
        (
            "version = 1\n[project]\ncontext = \"mixed\"\n[project.providers]\nssh = \"ghp_fictional_secret\"\n",
            "secret-shaped",
        ),
        (
            "version = 1\n[project]\ncontext = \"mixed\"\n[project.providers]\nssh = \"\"\n",
            "cannot be empty",
        ),
        (
            "version = 1\n[project]\ncontext = \"mixed\"\n[project.providers]\nssh = \"\\u001b[31munsafe\"\n",
            "unsafe display",
        ),
        (
            "version = 1\n[project]\ncontext = \"mixed\"\n[project.providers]\ntoken = \"ghp_fictional_secret\"\n",
            "invalid",
        ),
    ] {
        fixture.write_binding(binding);
        let output = fixture
            .command(&bin_directory)
            .args(["empireai"])
            .output()
            .unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(stderr.contains(diagnostic), "{stderr}");
        assert!(!stderr.contains("ghp_") && !stderr.contains('\u{1b}'));
        assert!(output.stdout.is_empty());
        assert!(!fixture.path.join("ssh-ran").exists());
    }
    fixture.write_binding("version = 1\n[project]\ncontext = \"mixed\"\n");
    let output = fixture
        .command(&bin_directory)
        .args(["gh"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("does not define the selected provider")
    );
    assert!(!fixture.path.join("ssh-ran").exists());
}

#[test]
fn shortcut_rejects_extra_arguments_before_any_provider_action() {
    let fixture = LoginFixture::new("shortcut-args");
    let bin_directory = fixture.configure_ssh(0);
    fixture.write_binding("version = 1\n[project]\ncontext = \"empire\"\n");
    for args in [
        vec!["empireai", "--", "arbitrary-command"],
        vec!["empireai", "--provider", "aws"],
        vec!["empireai", "--context"],
        vec!["empireai", "--context", "--print-command"],
        vec!["empireai", "--print-command", "--print-command"],
        vec!["empireai", "--context", "empire", "--context", "empire"],
    ] {
        let output = fixture.command(&bin_directory).args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .starts_with("usage:")
        );
        assert!(!fixture.path.join("ssh-ran").exists());
    }
}

#[test]
fn shortcut_refuses_binding_drift_during_login_planning() {
    for late in [false, true] {
        let fixture = LoginFixture::new("shortcut-drift");
        let bin_directory = fixture.configure_aws_console(0);
        fixture.write_binding("version = 1\n[project]\ncontext = \"aws-console\"\n[project.providers]\naws = \"aws-console\"\n");
        let aws = bin_directory.join("aws");
        let script = fs::read_to_string(&aws).unwrap();
        let mutation = format!(
            "#!/bin/sh\nprintf 'version = 1\\n[project]\\ncontext = \"aws-console\"\\n[project.providers]\\naws = \"changed\"\\n' > '{}'\n",
            fixture.path.join(".authmux.toml").display()
        );
        let mutation = if late {
            format!(
                "#!/bin/sh\nif [ \"$1 $2 $3\" = \"configure get login_session\" ]; then\nif [ -f '{}' ]; then\n{}else\n: > '{}'\nfi\nfi\n",
                fixture.path.join("planned").display(),
                mutation.trim_start_matches("#!/bin/sh\n"),
                fixture.path.join("planned").display()
            )
        } else {
            mutation
        };
        fs::write(aws, script.replacen("#!/bin/sh\n", &mutation, 1)).unwrap();
        let output = fixture
            .command(&bin_directory)
            .args(["aws"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(6), "{:?}", output.stderr);
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("context")
        );
        assert!(!fixture.path.join("aws-login-ran").exists());
    }
}

struct LoginFixture {
    path: PathBuf,
}

impl LoginFixture {
    fn command(&self, bin_directory: &std::path::Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_authmux"));
        command
            .current_dir(&self.path)
            .env("HOME", self.path.join("home"))
            .env("XDG_CONFIG_HOME", self.path.join("config"))
            .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()));
        command
    }

    fn write_binding(&self, source: &str) {
        fs::create_dir_all(self.path.join(".git")).unwrap();
        fs::write(self.path.join(".authmux.toml"), source).unwrap();
    }

    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos()
            % 1_000_000_000;
        #[cfg(target_os = "macos")]
        let temp_root = PathBuf::from("/private/tmp");
        #[cfg(not(target_os = "macos"))]
        let temp_root = std::env::temp_dir();
        let path = temp_root.join(format!("amux-cl-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).expect("fixture directory is created");
        Self { path }
    }

    fn configure_ssh(&self, exit_code: i32) -> PathBuf {
        self.write_config(
            "version = 1\n\
             [contexts.empire]\n\
             [contexts.empire.providers.ssh]\n\
             host_alias = \"empire-alpha\"\n\
             expected_remote_principal = \"researcher@example.invalid\"\n",
        );
        self.write_fake_ssh(exit_code)
    }

    fn configure_ssh_with_transport(
        &self,
        login_exit_code: i32,
        probe_exit_code: i32,
        active_socket: bool,
    ) -> (PathBuf, Option<UnixListener>) {
        let ssh_directory = self.path.join("home/.ssh");
        fs::create_dir_all(&ssh_directory).expect("fictional SSH directory is created");
        let control_path = ssh_directory.join("sockets/empire.sock");
        fs::create_dir_all(
            control_path
                .parent()
                .expect("fictional control socket has a parent"),
        )
        .expect("fictional SSH socket directory is created");
        self.write_config(&format!(
            "version = 1\n\
             [contexts.empire]\n\
             [contexts.empire.providers.ssh]\n\
             host_alias = \"empire-alpha\"\n\
             expected_remote_principal = \"researcher@example.invalid\"\n\
             control_path = \"{}\"\n",
            control_path.display()
        ));
        let listener = active_socket.then(|| {
            let listener =
                UnixListener::bind(&control_path).expect("fictional control socket is created");
            let mut permissions = fs::metadata(&control_path)
                .expect("fictional control socket metadata is readable")
                .permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(&control_path, permissions)
                .expect("fictional control socket permissions are protected");
            listener
        });
        (
            self.write_fake_ssh_with_probe(login_exit_code, probe_exit_code),
            listener,
        )
    }

    fn configure_gcp(&self, exit_code: i32) -> PathBuf {
        let home = self.path.join("home");
        fs::create_dir_all(home.join(".config/gcloud"))
            .expect("fictional gcloud directory is created");
        self.write_config(&format!(
            "version = 1\n\
             [contexts.crm.providers.gcp.gcloud]\n\
             config_dir = \"{}\"\n\
             configuration = \"crm-research\"\n\
             expected_principal = \"researcher@example.invalid\"\n\
             expected_project = \"fictional-project\"\n",
            home.join(".config/gcloud").display()
        ));
        self.write_fake_gcloud(exit_code)
    }

    fn configure_aws_console(&self, exit_code: i32) -> PathBuf {
        self.write_config(
            "version = 1\n\
             [contexts.aws-console.providers.aws]\n\
             profile = \"cornell-development\"\n\
             expected_account = \"111111111111\"\n",
        );
        self.write_fake_aws_console(exit_code)
    }

    fn configure_aws_sso(&self, exit_code: i32) -> PathBuf {
        self.write_config(
            "version = 1\n\
             [contexts.aws-sso.providers.aws]\n\
             profile = \"research-sso\"\n\
             expected_account = \"222222222222\"\n",
        );
        self.write_fake_aws_sso(exit_code)
    }

    fn configure_aws_role_source(&self, exit_code: i32) -> PathBuf {
        self.write_config(
            "version = 1\n\
             [contexts.aws-role.providers.aws]\n\
             profile = \"workload-operator\"\n\
             expected_account = \"333333333333\"\n",
        );
        self.write_fake_aws_role_source(exit_code)
    }

    fn configure_impersonated_gcp(&self, exit_code: i32) -> PathBuf {
        let home = self.path.join("home");
        fs::create_dir_all(home.join(".config/gcloud"))
            .expect("fictional gcloud directory is created");
        self.write_config(&format!(
            "version = 1\n\
             [contexts.crm.providers.gcp.gcloud]\n\
             config_dir = \"{}\"\n\
             configuration = \"crm-research\"\n\
             expected_principal = \"workload@example.invalid\"\n\
             expected_source_account = \"researcher@example.invalid\"\n\
             expected_project = \"fictional-project\"\n",
            home.join(".config/gcloud").display()
        ));
        self.write_fake_gcloud(exit_code)
    }

    fn configure_adc_only_gcp(&self) -> PathBuf {
        let home = self.path.join("home");
        let adc_file = home.join(".config/gcloud/adc/crm.json");
        fs::create_dir_all(adc_file.parent().expect("ADC fixture has a parent"))
            .expect("fictional ADC directory is created");
        fs::write(&adc_file, "fictional contents are never opened")
            .expect("fictional ADC file is written");
        self.write_config(&format!(
            "version = 1\n\
             [contexts.crm.providers.gcp.adc]\n\
             mode = \"credential_file\"\n\
             credential_file = \"{}\"\n\
             expected_principal = \"workload@example.invalid\"\n",
            adc_file.display()
        ));
        self.write_fake_gcloud(0)
    }

    fn configure_signaling_gcp(&self) -> PathBuf {
        let directory = self.configure_gcp(0);
        let gcloud = directory.join("gcloud");
        fs::write(&gcloud, "#!/bin/sh\nkill -TERM $$\n")
            .expect("signaling gcloud fixture is written");
        let mut permissions = fs::metadata(&gcloud)
            .expect("signaling gcloud metadata is readable")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&gcloud, permissions).expect("signaling gcloud is executable");
        directory
    }

    fn configure_mixed(&self) -> PathBuf {
        self.write_config(
            "version = 1\n\
             [contexts.mixed]\n\
             [contexts.mixed.providers.aws]\n\
             profile = \"fictional-profile\"\n\
             expected_account = \"111111111111\"\n\
             [contexts.mixed.providers.ssh]\n\
             host_alias = \"empire-alpha\"\n\
             expected_remote_principal = \"researcher@example.invalid\"\n",
        );
        self.write_fake_ssh(0)
    }

    fn write_config(&self, source: &str) {
        let directory = self.path.join("config/authmux");
        fs::create_dir_all(&directory).expect("config directory is created");
        fs::write(directory.join("config.toml"), source).expect("user config is written");
    }

    fn write_fake_ssh(&self, exit_code: i32) -> PathBuf {
        self.write_fake_ssh_with_probe(exit_code, 97)
    }

    fn write_fake_ssh_with_probe(&self, exit_code: i32, probe_exit_code: i32) -> PathBuf {
        let directory = self.path.join("bin");
        fs::create_dir_all(&directory).expect("bin directory is created");
        let ssh = directory.join("ssh");
        fs::write(
            &ssh,
            format!(
                "#!/bin/sh\n\
                 if [ \"$1\" = \"-F\" ]; then : > '{}'; exit {probe_exit_code}; fi\n\
                 : > '{}'\n\
                 printf 'native argv: %s\\n' \"$1\"\n\
                 if [ -n \"${{GH_TOKEN+x}}\" ]; then printf 'inherited GH_TOKEN: present\\n'; else printf 'inherited GH_TOKEN: absent\\n'; fi\n\
                 exit {exit_code}\n",
                self.path.join("ssh-status-ran").display(),
                self.path.join("ssh-ran").display()
            ),
        )
        .expect("fake ssh is written");
        let mut permissions = fs::metadata(&ssh)
            .expect("fake ssh metadata is readable")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&ssh, permissions).expect("fake ssh is executable");
        directory
    }

    fn write_fake_gcloud(&self, exit_code: i32) -> PathBuf {
        let directory = self.path.join("bin");
        fs::create_dir_all(&directory).expect("bin directory is created");
        let gcloud = directory.join("gcloud");
        fs::write(
            &gcloud,
            format!(
                "#!/bin/sh\n\
                 : > '{}'\n\
                 printf 'native argv: %s|%s|%s|%s|%s\\n' \"$1\" \"$2\" \"$3\" \"$4\" \"$5\"\n\
                 printf 'CLOUDSDK_CONFIG=%s\\n' \"$CLOUDSDK_CONFIG\"\n\
                 printf 'CLOUDSDK_ACTIVE_CONFIG_NAME=%s\\n' \"$CLOUDSDK_ACTIVE_CONFIG_NAME\"\n\
                 if [ -n \"${{CLOUDSDK_CORE_DISABLE_PROMPTS+x}}\" ]; then printf 'CLOUDSDK_CORE_DISABLE_PROMPTS=present\\n'; else printf 'CLOUDSDK_CORE_DISABLE_PROMPTS=absent\\n'; fi\n\
                 printf 'CLOUDSDK_CORE_DISABLE_FILE_LOGGING=%s\\n' \"$CLOUDSDK_CORE_DISABLE_FILE_LOGGING\"\n\
                 printf 'CLOUDSDK_CORE_DISABLE_USAGE_REPORTING=%s\\n' \"$CLOUDSDK_CORE_DISABLE_USAGE_REPORTING\"\n\
                 printf 'CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK=%s\\n' \"$CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK\"\n\
                 if [ -n \"${{GOOGLE_APPLICATION_CREDENTIALS+x}}\" ]; then printf 'GOOGLE_APPLICATION_CREDENTIALS=present\\n'; else printf 'GOOGLE_APPLICATION_CREDENTIALS=absent\\n'; fi\n\
                 exit {exit_code}\n",
                self.path.join("gcloud-ran").display()
            ),
        )
        .expect("fake gcloud is written");
        let mut permissions = fs::metadata(&gcloud)
            .expect("fake gcloud metadata is readable")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&gcloud, permissions).expect("fake gcloud is executable");
        directory
    }

    fn write_fake_aws_console(&self, exit_code: i32) -> PathBuf {
        let directory = self.path.join("bin");
        fs::create_dir_all(&directory).expect("bin directory is created");
        let aws = directory.join("aws");
        fs::write(
            &aws,
            format!(
                "#!/bin/sh\n\
                 if [ \"$1 $2 $3\" = \"configure get login_session\" ]; then printf 'arn:aws:iam::111111111111:user/fictional-developer\\n'; exit 0; fi\n\
                 if [ \"$1 $2 $3\" = \"configure get sso_account_id\" ]; then exit 1; fi\n\
                 if [ \"$1\" = \"login\" ]; then\n\
                   : > '{}'\n\
                   printf 'native argv: %s|%s|%s|%s\\n' \"$1\" \"$2\" \"$3\" \"$4\"\n\
                   printf 'AWS_PROFILE=%s\\n' \"$AWS_PROFILE\"\n\
                   if [ -n \"${{AWS_ACCESS_KEY_ID+x}}\" ]; then printf 'inherited AWS_ACCESS_KEY_ID: present\\n'; else printf 'inherited AWS_ACCESS_KEY_ID: absent\\n'; fi\n\
                   exit {exit_code}\n\
                 fi\n\
                 exit 64\n",
                self.path.join("aws-login-ran").display()
            ),
        )
        .expect("fake aws is written");
        let mut permissions = fs::metadata(&aws)
            .expect("fake aws metadata is readable")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&aws, permissions).expect("fake aws is executable");
        directory
    }

    fn write_fake_aws_sso(&self, exit_code: i32) -> PathBuf {
        let directory = self.path.join("bin");
        fs::create_dir_all(&directory).expect("bin directory is created");
        let aws = directory.join("aws");
        fs::write(
            &aws,
            format!(
                "#!/bin/sh\n\
                 if [ \"$1 $2 $3\" = \"configure get login_session\" ]; then exit 1; fi\n\
                 if [ \"$1 $2 $3\" = \"configure get sso_account_id\" ]; then printf '222222222222\\n'; exit 0; fi\n\
                 if [ \"$1 $2\" = \"sso login\" ]; then\n\
                   : > '{}'\n\
                   printf 'native argv: %s|%s|%s|%s|%s\\n' \"$1\" \"$2\" \"$3\" \"$4\" \"$5\"\n\
                   exit {exit_code}\n\
                 fi\n\
                 exit 64\n",
                self.path.join("aws-sso-login-ran").display()
            ),
        )
        .expect("fake aws is written");
        let mut permissions = fs::metadata(&aws)
            .expect("fake aws metadata is readable")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&aws, permissions).expect("fake aws is executable");
        directory
    }

    fn write_fake_aws_role_source(&self, exit_code: i32) -> PathBuf {
        let directory = self.path.join("bin");
        fs::create_dir_all(&directory).expect("bin directory is created");
        let aws = directory.join("aws");
        fs::write(
            &aws,
            format!(
                "#!/bin/sh\n\
                 if [ \"$1 $2 $3 $4 $5\" = \"configure get role_arn --profile workload-operator\" ]; then printf 'arn:aws:iam::333333333333:role/fictional-workload-operator\\n'; exit 0; fi\n\
                 if [ \"$1 $2 $3 $4 $5\" = \"configure get source_profile --profile workload-operator\" ]; then printf 'source-console\\n'; exit 0; fi\n\
                 if [ \"$1 $2 $3 $4 $5\" = \"configure get login_session --profile source-console\" ]; then printf 'arn:aws:iam::111111111111:user/fictional-developer\\n'; exit 0; fi\n\
                 if [ \"$1 $2 $3 $4 $5\" = \"configure get sso_account_id --profile source-console\" ]; then exit 1; fi\n\
                 if [ \"$1\" = \"configure\" ]; then exit 1; fi\n\
                 if [ \"$1\" = \"login\" ]; then\n\
                   : > '{}'\n\
                   exit {exit_code}\n\
                 fi\n\
                 exit 64\n",
                self.path.join("aws-role-login-ran").display()
            ),
        )
        .expect("fake aws is written");
        let mut permissions = fs::metadata(&aws)
            .expect("fake aws metadata is readable")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&aws, permissions).expect("fake aws is executable");
        directory
    }
}

impl Drop for LoginFixture {
    fn drop(&mut self) {
        match fs::remove_dir_all(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("fixture cleanup failed: {error}"),
        }
    }
}

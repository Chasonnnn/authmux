#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn exec_refuses_a_fictional_aws_account_mismatch() {
    let fixture = FixtureDirectory::new("mismatch");
    let bin_directory = fixture.configure_aws("222222222222");

    let marker = fixture.path.join("child-ran");
    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args([
            "exec",
            "--context",
            "crm",
            "--",
            "/usr/bin/touch",
            marker.to_str().expect("fixture path is Unicode"),
        ])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(3), "stderr: {stderr}");
    assert!(!marker.exists(), "mismatched identity must block the child");
    assert_eq!(
        stderr,
        "refusing child execution: expected AWS account 111111111111, but provider reported 222222222222\n"
    );
}

#[test]
fn exec_emits_a_structured_reauthentication_event_for_an_expired_aws_session() {
    let fixture = FixtureDirectory::new("expired-session-event");
    let bin_directory = fixture.configure_expired_aws();
    let marker = fixture.path.join("child-ran");

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args([
            "exec",
            "--context",
            "crm",
            "--",
            "/usr/bin/touch",
            marker.to_str().expect("fixture path is Unicode"),
        ])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stderr = String::from_utf8(output.stderr).expect("event is UTF-8");
    assert_eq!(output.status.code(), Some(10), "stderr: {stderr}");
    assert!(output.stdout.is_empty());
    assert!(!marker.exists(), "expired Session must block the child");
    assert_eq!(
        stderr,
        "{\"schema_version\":1,\"event\":\"reauthentication_required\",\"context\":\"crm\",\"provider\":\"aws\",\"login_argv\":[\"authmux\",\"login\",\"crm\",\"--provider\",\"aws\",\"--print-command\"],\"retry\":\"original_command_once\"}\n"
    );
    assert!(!stderr.contains("AKIA1111111111111111"));
}

#[test]
fn exec_runs_a_matching_context_with_the_child_exit_code() {
    let fixture = FixtureDirectory::new("matching");
    let bin_directory = fixture.configure_aws("111111111111");

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args([
            "exec",
            "--context",
            "crm",
            "--",
            "/bin/sh",
            "-c",
            "test \"$AWS_PROFILE\" = 'crm-development' && exit 23",
        ])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(23), "stderr: {stderr}");
    assert!(stderr.is_empty());
}

#[test]
fn exec_uses_the_repository_root_project_binding_when_context_is_omitted() {
    let fixture = FixtureDirectory::new("project-binding");
    let bin_directory = fixture.configure_aws("111111111111");
    let nested_directory = fixture.configure_project_binding("crm");

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args([
            "exec",
            "--",
            "/bin/sh",
            "-c",
            "test \"$AWS_PROFILE\" = 'crm-development' && exit 29",
        ])
        .current_dir(nested_directory)
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(29), "stderr: {stderr}");
    assert!(stderr.is_empty());
}

#[test]
fn exec_does_not_search_for_a_binding_above_the_repository_root() {
    let fixture = FixtureDirectory::new("binding-boundary");
    let bin_directory = fixture.configure_aws("111111111111");
    let repository = fixture.path.join("repository");
    fs::create_dir_all(repository.join(".git")).expect("repository marker is created");
    fs::write(
        fixture.path.join(".authmux.toml"),
        "version = 1\n[project]\ncontext = \"crm\"\n",
    )
    .expect("out-of-scope parent binding is written");

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["exec", "--", "/usr/bin/true"])
        .current_dir(repository)
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert_eq!(
        stderr,
        "project binding is not configured at the repository root\n"
    );
}

#[test]
fn exec_terminates_with_the_child_signal() {
    let fixture = FixtureDirectory::new("child-signal");
    let bin_directory = fixture.configure_aws("111111111111");

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args([
            "exec",
            "--context",
            "crm",
            "--",
            "/bin/sh",
            "-c",
            "kill -TERM $$",
        ])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.signal(), Some(15), "stderr: {stderr}");
    assert!(stderr.is_empty());
}

#[test]
fn exec_inherits_only_the_documented_environment_allowlist() {
    let fixture = FixtureDirectory::new("environment-allowlist");
    let bin_directory = fixture.configure_aws("111111111111");

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["exec", "--context", "crm", "--", "/usr/bin/env"])
        .env_clear()
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .env("HOME", "/fictional/home")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("TERM", "xterm-fictional")
        .env("AWS_SECRET_ACCESS_KEY", "fictional-secret-must-not-pass")
        .env("AWS_SESSION_TOKEN", "fictional-session-must-not-pass")
        .env("GH_TOKEN", "ghp_fictional_must_not_pass")
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("environment is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    let mut environment = stdout.lines().collect::<Vec<_>>();
    environment.sort_unstable();
    assert_eq!(
        environment,
        [
            "AWS_PROFILE=crm-development",
            "HOME=/fictional/home",
            "LANG=C",
            "LC_ALL=C",
            &format!("PATH={}:/usr/bin:/bin", bin_directory.display()),
            "TERM=xterm-fictional",
        ]
    );
    assert!(!stdout.contains("fictional-secret-must-not-pass"));
    assert!(!stdout.contains("fictional-session-must-not-pass"));
    assert!(!stdout.contains("ghp_fictional_must_not_pass"));
    assert!(stderr.is_empty());
}

#[test]
fn exec_preserves_hostile_arguments_as_literal_values() {
    let fixture = FixtureDirectory::new("literal-arguments");
    let bin_directory = fixture.configure_aws("111111111111");
    let marker = fixture.path.join("shell-interpolation-ran");
    let shell_like = format!("$(touch {})", marker.display());

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args([
            "exec",
            "--context",
            "crm",
            "--",
            "/usr/bin/printf",
            "<%s>\n",
            "space value",
            "雪",
            "--leading-dash",
        ])
        .arg(&shell_like)
        .args(["semi;colon", "*"])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("literal output is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(
        stdout,
        format!("<space value>\n<雪>\n<--leading-dash>\n<{shell_like}>\n<semi;colon>\n<*>\n")
    );
    assert!(
        !marker.exists(),
        "shell-shaped argument must remain literal"
    );
    assert!(stderr.is_empty());
}

#[test]
fn concurrent_contexts_keep_their_aws_profiles_isolated() {
    let fixture = FixtureDirectory::new("concurrent-contexts");
    let bin_directory = fixture.configure_two_aws_contexts();
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_authmux"));
    let config_home = fixture.path.join("config");
    let path = format!("{}:/usr/bin:/bin", bin_directory.display());

    let handles = [
        ("crm", "crm-development"),
        ("analytics", "analytics-readonly"),
    ]
    .map(|(context, expected_profile)| {
        let executable = executable.clone();
        let config_home = config_home.clone();
        let path = path.clone();
        thread::spawn(move || {
            let output = Command::new(executable)
                .args([
                    "exec",
                    "--context",
                    context,
                    "--",
                    "/usr/bin/printenv",
                    "AWS_PROFILE",
                ])
                .env("XDG_CONFIG_HOME", config_home)
                .env("PATH", path)
                .output()
                .expect("authmux runs");
            (output, expected_profile)
        })
    });

    for handle in handles {
        let (output, expected_profile) = handle.join().expect("authmux thread completes");
        let stdout = String::from_utf8(output.stdout).expect("profile output is UTF-8");
        let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
        assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
        assert_eq!(stdout, format!("{expected_profile}\n"));
        assert!(stderr.is_empty());
    }
}

#[test]
fn exec_refuses_a_context_changed_during_provider_validation() {
    let fixture = FixtureDirectory::new("context-reresolution");
    let bin_directory = fixture.configure_aws_that_rewrites_context();
    let marker = fixture.path.join("child-ran-after-context-change");

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args([
            "exec",
            "--context",
            "crm",
            "--",
            "/usr/bin/touch",
            marker.to_str().expect("fixture marker is Unicode"),
        ])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(6), "stderr: {stderr}");
    assert_eq!(
        stderr,
        "refusing child execution: authentication context changed after provider validation; retry the command\n"
    );
    assert!(
        !marker.exists(),
        "a child must not run with a context changed after validation"
    );
}

#[test]
fn exec_rejects_ssh_only_context_before_observation_or_child_spawn() {
    let fixture = FixtureDirectory::new("ssh-exec-unsupported");
    let bin_directory = fixture.configure_ssh_context();
    let child_marker = fixture.path.join("child-ran");

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args([
            "exec",
            "--context",
            "empire",
            "--",
            "/usr/bin/touch",
            child_marker.to_str().expect("fixture path is UTF-8"),
        ])
        .env("XDG_CONFIG_HOME", fixture.path.join("config"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("report is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert_eq!(output.status.code(), Some(2));
    assert!(stdout.is_empty());
    assert_eq!(
        stderr,
        "requested authentication context does not define AWS required by this command\n"
    );
    assert!(!child_marker.exists(), "SSH exec must not spawn the child");
    assert!(
        !fixture.path.join("provider-ran").exists(),
        "SSH exec must not observe a provider"
    );
}

struct FixtureDirectory {
    path: PathBuf,
}

impl FixtureDirectory {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after the Unix epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("authmux-{label}-{}-{unique}", std::process::id()));
        fs::create_dir(&path).expect("fixture directory is created");
        Self { path }
    }

    fn configure_aws(&self, observed_account: &str) -> PathBuf {
        let bin_directory = self.path.join("bin");
        let config_directory = self.path.join("config").join("authmux");
        fs::create_dir_all(&bin_directory).expect("fixture bin directory is created");
        fs::create_dir_all(&config_directory).expect("fixture config directory is created");

        let aws = bin_directory.join("aws");
        fs::write(
            &aws,
            format!(
                "#!/bin/sh\n\
                 if [ \"$1 $2 $3 $4 $5 $6 $7 $8\" = \"sts get-caller-identity --query Account --output text --no-cli-pager --no-cli-auto-prompt\" ]; then\n\
                   printf '{observed_account}\\n'\n\
                   exit 0\n\
                 fi\n\
                 exit 64\n"
            ),
        )
        .expect("fictional aws fixture is written");
        let mut permissions = fs::metadata(&aws)
            .expect("fixture metadata is readable")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&aws, permissions).expect("fictional aws fixture is executable");

        fs::write(
            config_directory.join("config.toml"),
            "version = 1\n\
             [contexts.crm.providers.aws]\n\
             profile = \"crm-development\"\n\
             expected_account = \"111111111111\"\n",
        )
        .expect("fictional user config is written");

        bin_directory
    }

    fn configure_expired_aws(&self) -> PathBuf {
        let bin_directory = self.path.join("bin");
        let config_directory = self.path.join("config").join("authmux");
        fs::create_dir_all(&bin_directory).expect("fixture bin directory is created");
        fs::create_dir_all(&config_directory).expect("fixture config directory is created");

        let aws = bin_directory.join("aws");
        fs::write(
            &aws,
            "#!/bin/sh\n\
             if [ \"$1 $2 $3 $4 $5 $6 $7 $8\" = \"sts get-caller-identity --query Account --output text --no-cli-pager --no-cli-auto-prompt\" ]; then\n\
               printf 'Error when retrieving an SSO session: cached session expired; AKIA1111111111111111\\n' >&2\n\
               exit 1\n\
             fi\n\
             exit 64\n",
        )
        .expect("fictional expired AWS fixture is written");
        let mut permissions = fs::metadata(&aws)
            .expect("fixture metadata is readable")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&aws, permissions).expect("fictional aws fixture is executable");

        fs::write(
            config_directory.join("config.toml"),
            "version = 1\n\
             [contexts.crm.providers.aws]\n\
             profile = \"crm-development\"\n\
             expected_account = \"111111111111\"\n",
        )
        .expect("fictional user config is written");

        bin_directory
    }

    fn configure_two_aws_contexts(&self) -> PathBuf {
        let bin_directory = self.path.join("bin");
        let config_directory = self.path.join("config").join("authmux");
        fs::create_dir_all(&bin_directory).expect("fixture bin directory is created");
        fs::create_dir_all(&config_directory).expect("fixture config directory is created");

        let aws = bin_directory.join("aws");
        fs::write(
            &aws,
            "#!/bin/sh\n\
             if [ \"$1 $2 $3 $4 $5 $6 $7 $8\" = \"sts get-caller-identity --query Account --output text --no-cli-pager --no-cli-auto-prompt\" ]; then\n\
               case \"$AWS_PROFILE\" in\n\
                 crm-development) printf '111111111111\\n'; exit 0 ;;\n\
                 analytics-readonly) printf '222222222222\\n'; exit 0 ;;\n\
               esac\n\
             fi\n\
             exit 64\n",
        )
        .expect("fictional aws fixture is written");
        let mut permissions = fs::metadata(&aws)
            .expect("fixture metadata is readable")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&aws, permissions).expect("fictional aws fixture is executable");

        fs::write(
            config_directory.join("config.toml"),
            "version = 1\n\
             [contexts.crm.providers.aws]\n\
             profile = \"crm-development\"\n\
             expected_account = \"111111111111\"\n\
             [contexts.analytics.providers.aws]\n\
             profile = \"analytics-readonly\"\n\
             expected_account = \"222222222222\"\n",
        )
        .expect("fictional user config is written");

        bin_directory
    }

    fn configure_ssh_context(&self) -> PathBuf {
        let bin_directory = self.path.join("bin");
        let config_directory = self.path.join("config").join("authmux");
        fs::create_dir_all(&bin_directory).expect("fixture bin directory is created");
        fs::create_dir_all(&config_directory).expect("fixture config directory is created");
        let provider_marker = self.path.join("provider-ran");
        let ssh = bin_directory.join("ssh");
        fs::write(
            &ssh,
            format!(
                "#!/bin/sh\ntouch '{}'\nexit 97\n",
                provider_marker.display()
            ),
        )
        .expect("fictional SSH fixture is written");
        let mut permissions = fs::metadata(&ssh)
            .expect("fixture metadata is readable")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&ssh, permissions).expect("fictional SSH fixture is executable");
        fs::write(
            config_directory.join("config.toml"),
            "version = 1\n\
             [contexts.empire.providers.ssh]\n\
             host_alias = \"empire-alpha\"\n\
             expected_remote_principal = \"researcher@example.invalid\"\n",
        )
        .expect("fictional SSH user config is written");
        bin_directory
    }

    fn configure_aws_that_rewrites_context(&self) -> PathBuf {
        let bin_directory = self.path.join("bin");
        let config_directory = self.path.join("config").join("authmux");
        fs::create_dir_all(&bin_directory).expect("fixture bin directory is created");
        fs::create_dir_all(&config_directory).expect("fixture config directory is created");
        let config_file = config_directory.join("config.toml");
        fs::write(
            &config_file,
            "version = 1\n\
             [contexts.crm.providers.aws]\n\
             profile = \"crm-development\"\n\
             expected_account = \"111111111111\"\n",
        )
        .expect("initial fictional user config is written");

        let aws = bin_directory.join("aws");
        fs::write(
            &aws,
            format!(
                "#!/bin/sh\n\
                 if [ \"$1 $2 $3 $4 $5 $6 $7 $8\" = \"sts get-caller-identity --query Account --output text --no-cli-pager --no-cli-auto-prompt\" ]; then\n\
                   printf 'version = 1\\n[contexts.crm.providers.aws]\\nprofile = \"crm-production\"\\nexpected_account = \"222222222222\"\\n' > '{}'\n\
                   printf '111111111111\\n'\n\
                   exit 0\n\
                 fi\n\
                 exit 64\n",
                config_file.display()
            ),
        )
        .expect("fictional rewriting AWS fixture is written");
        let mut permissions = fs::metadata(&aws)
            .expect("fixture metadata is readable")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&aws, permissions).expect("fictional aws fixture is executable");

        bin_directory
    }

    fn configure_project_binding(&self, context_name: &str) -> PathBuf {
        fs::create_dir_all(self.path.join(".git")).expect("repository marker is created");
        fs::write(
            self.path.join(".authmux.toml"),
            format!("version = 1\n[project]\ncontext = \"{context_name}\"\n"),
        )
        .expect("fictional project binding is written");
        let nested_directory = self.path.join("nested").join("worktree");
        fs::create_dir_all(&nested_directory).expect("nested directory is created");
        nested_directory
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        remove_fixture(&self.path);
    }
}

fn remove_fixture(path: &Path) {
    match fs::remove_dir_all(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("fixture cleanup failed: {error}"),
    }
}

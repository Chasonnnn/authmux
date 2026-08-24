#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn github_status_validates_the_selected_login_without_exposing_a_token() {
    let fixture = GithubCliFixture::new("status-success");
    let bin_directory = fixture.configure_gh("success", "fictional-researcher", "keyring", 0);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["status", "--context", "github", "--provider", "github"])
        .env("HOME", fixture.home())
        .env("XDG_CONFIG_HOME", fixture.authmux_config_root())
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .env("GH_TOKEN", "ghp_fictional_must_not_pass")
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(stdout.contains("context: github\nprovider: github\n"));
    assert!(stdout.contains("profile: github.com\n"));
    assert!(stdout.contains("expected identity: fictional-researcher\n"));
    assert!(stdout.contains("observed identity: fictional-researcher\n"));
    assert!(stdout.contains("identity match: match\n"));
    assert!(stdout.contains("session usability: usable\n"));
    assert!(stdout.contains("evidence level: provider_validation\n"));
    assert!(stdout.contains("provider contacted: yes\n"));
    assert!(!stdout.contains("ghp_"));
    assert!(stderr.is_empty());

    let invocation = fs::read_to_string(fixture.invocation()).expect("invocation was recorded");
    assert_eq!(
        invocation,
        format!(
            "argv=auth|status|--active|--hostname|github.com|--json|hosts\n\
             GH_CONFIG_DIR={}\n\
             GH_TOKEN=absent\n",
            fixture.github_config_dir().display()
        )
    );
}

#[test]
fn status_all_observes_every_configured_context_without_a_project_binding() {
    let fixture = GithubCliFixture::new("status-all");
    let bin_directory = fixture.configure_gh("success", "fictional-researcher", "keyring", 0);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["status", "--all"])
        .current_dir(fixture.home())
        .env("HOME", fixture.home())
        .env("XDG_CONFIG_HOME", fixture.authmux_config_root())
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(stdout.starts_with("authentication status: 1 context\n\n"));
    assert!(stdout.contains("context: github\nprovider: github\n"));
    assert!(stdout.contains("identity match: match\n"));
    assert!(stdout.contains("session usability: usable\n"));
    assert!(stderr.is_empty());
}

#[test]
fn status_all_json_is_machine_readable_and_preserves_provider_evidence() {
    let fixture = GithubCliFixture::new("status-all-json");
    let bin_directory = fixture.configure_gh("success", "fictional-researcher", "keyring", 0);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["status", "--all", "--json"])
        .current_dir(fixture.home())
        .env("HOME", fixture.home())
        .env("XDG_CONFIG_HOME", fixture.authmux_config_root())
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("status is valid JSON");
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["command"], "status_all");
    assert_eq!(document["contexts"].as_array().map(Vec::len), Some(1));
    assert_eq!(document["contexts"][0]["context"], "github");
    assert_eq!(
        document["contexts"][0]["observations"][0]["provider"],
        "github"
    );
    assert_eq!(
        document["contexts"][0]["observations"][0]["identity_match"],
        "match"
    );
    assert!(stderr.is_empty());
}

#[test]
fn github_login_delegates_to_gh_and_validates_the_selected_login_afterward() {
    let fixture = GithubCliFixture::new("login-success");
    let bin_directory = fixture.configure_gh_login();

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "github", "--provider", "github"])
        .env("HOME", fixture.home())
        .env("XDG_CONFIG_HOME", fixture.authmux_config_root())
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .env("GH_TOKEN", "ghp_fictional_must_not_pass")
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(stdout.starts_with(
        "login: github\n\
         provider: github\n\
         GitHub hostname: github.com\n\
         expected GitHub login: fictional-researcher\n\
         native command: gh auth login --hostname github.com --web --skip-ssh-key\n"
    ));
    assert!(stdout.contains("native login GH_TOKEN=absent\n"));
    assert!(stdout.contains("post-login identity match: match\n"));
    assert!(stdout.contains("post-login session usability: usable\n"));
    assert!(!stdout.contains("ghp_"));
    assert!(stderr.is_empty());
}

#[test]
fn github_login_can_print_an_external_terminal_handoff_without_starting_native_login() {
    let fixture = GithubCliFixture::new("login-print-command");
    let bin_directory = fixture.configure_gh_login();

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["login", "github", "--provider", "github", "--print-command"])
        .env("HOME", fixture.home())
        .env("XDG_CONFIG_HOME", fixture.authmux_config_root())
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .env("GH_TOKEN", "ghp_fictional_must_not_pass")
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(
        stdout,
        "login: github\n\
         provider: github\n\
         GitHub hostname: github.com\n\
         expected GitHub login: fictional-researcher\n\
         native command: gh auth login --hostname github.com --web --skip-ssh-key\n\
         handoff: rerun this authmux login in an external terminal without --print-command; authmux did not start the native command\n"
    );
    assert!(stderr.is_empty());
}

#[test]
fn github_exec_validates_identity_then_runs_the_child_with_process_scoped_selection() {
    let fixture = GithubCliFixture::new("exec-success");
    let bin_directory = fixture.configure_gh_exec();

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args([
            "exec",
            "--context",
            "github",
            "--",
            "gh",
            "repo",
            "view",
            "fictional/repository",
        ])
        .env("HOME", fixture.home())
        .env("XDG_CONFIG_HOME", fixture.authmux_config_root())
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .env("GH_TOKEN", "ghp_fictional_must_not_pass")
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert_eq!(
        stdout,
        format!(
            "child argv=repo|view|fictional/repository\n\
             child GH_CONFIG_DIR={}\n\
             child GH_HOST=github.com\n\
             child GH_PROMPT_DISABLED=1\n\
             child GH_TOKEN=absent\n",
            fixture.github_config_dir().display()
        )
    );
    assert!(stderr.is_empty());
}

#[test]
fn github_doctor_checks_local_readiness_without_contacting_github() {
    let fixture = GithubCliFixture::new("doctor");
    let bin_directory = fixture.configure_gh_doctor();

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["doctor", "--context", "github", "--provider", "github"])
        .env("HOME", fixture.home())
        .env("XDG_CONFIG_HOME", fixture.authmux_config_root())
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(stdout.contains("doctor: github\nresult: warning\nprovider contacted: no\n"));
    assert!(stdout.contains("- [pass] configuration: GitHub Provider Profile resolved\n"));
    assert!(stdout.contains("- [pass] gh_cli: GitHub CLI 2.96.0 is supported\n"));
    assert!(stdout.contains(
        "- [warning] session_continuity: GitHub has no supported automatic Credential renewal contract; an unusable Session requires external login\n"
    ));
    assert!(stderr.is_empty());
}

#[test]
fn context_inspection_shows_github_intent_without_exposing_the_config_path() {
    let fixture = GithubCliFixture::new("context-inspection");

    for arguments in [
        vec!["context", "show", "--context", "github"],
        vec!["context", "list"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
            .args(arguments)
            .env("HOME", fixture.home())
            .env("XDG_CONFIG_HOME", fixture.authmux_config_root())
            .env("PATH", "/usr/bin:/bin")
            .output()
            .expect("authmux runs");
        let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
        let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
        assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
        assert!(stdout.contains("GitHub hostname: github.com\n"));
        assert!(stdout.contains("expected GitHub login: fictional-researcher\n"));
        assert!(!stdout.contains(&fixture.github_config_dir().display().to_string()));
        assert!(stderr.is_empty());
    }
}

#[test]
fn github_status_rejects_plaintext_native_credential_storage() {
    let fixture = GithubCliFixture::new("plaintext-storage");
    let bin_directory = fixture.configure_gh("success", "fictional-researcher", "oauth_token", 0);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["status", "--context", "github"])
        .env("HOME", fixture.home())
        .env("XDG_CONFIG_HOME", fixture.authmux_config_root())
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    assert_eq!(output.status.code(), Some(5));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr is UTF-8"),
        "provider status failed: GitHub credential is not stored in the system credential store\n"
    );
}

#[test]
fn github_exec_blocks_an_unexpected_active_login_before_spawning_the_child() {
    let fixture = GithubCliFixture::new("identity-mismatch");
    let bin_directory = fixture.configure_gh("success", "unexpected-user", "keyring", 0);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args([
            "exec",
            "--context",
            "github",
            "--",
            "gh",
            "repo",
            "view",
            "fictional/repository",
        ])
        .env("HOME", fixture.home())
        .env("XDG_CONFIG_HOME", fixture.authmux_config_root())
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr is UTF-8"),
        "refusing child execution: GitHub identity does not match the Expected Identity\n"
    );
}

#[test]
fn github_exec_emits_a_structured_reauthentication_event_for_an_unusable_session() {
    let fixture = GithubCliFixture::new("session-unusable");
    let bin_directory = fixture.configure_gh("failure", "fictional-researcher", "keyring", 0);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args([
            "exec",
            "--context",
            "github",
            "--",
            "gh",
            "repo",
            "view",
            "fictional/repository",
        ])
        .env("HOME", fixture.home())
        .env("XDG_CONFIG_HOME", fixture.authmux_config_root())
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    assert_eq!(output.status.code(), Some(10));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr is UTF-8"),
        "{\"schema_version\":1,\"event\":\"reauthentication_required\",\"context\":\"github\",\"provider\":\"github\",\"login_argv\":[\"authmux\",\"login\",\"github\",\"--provider\",\"github\",\"--print-command\"],\"retry\":\"original_command_once\"}\n"
    );
}

#[test]
fn github_exec_emits_the_reauthentication_event_when_the_selected_host_is_missing() {
    let fixture = GithubCliFixture::new("session-missing");
    let bin_directory = fixture.configure_gh_missing_host();

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args([
            "exec",
            "--context",
            "github",
            "--",
            "gh",
            "repo",
            "view",
            "fictional/repository",
        ])
        .env("HOME", fixture.home())
        .env("XDG_CONFIG_HOME", fixture.authmux_config_root())
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    assert_eq!(output.status.code(), Some(10));
    assert!(output.stdout.is_empty());
    assert!(!fixture.path.join("child-ran").exists());
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr is UTF-8"),
        "{\"schema_version\":1,\"event\":\"reauthentication_required\",\"context\":\"github\",\"provider\":\"github\",\"login_argv\":[\"authmux\",\"login\",\"github\",\"--provider\",\"github\",\"--print-command\"],\"retry\":\"original_command_once\"}\n"
    );
}

#[test]
fn status_all_keeps_the_configured_context_count_when_a_provider_fails() {
    let fixture = GithubCliFixture::new("status-all-provider-failure");
    let bin_directory = fixture.configure_gh("success", "fictional-researcher", "oauth_token", 0);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["status", "--all"])
        .current_dir(fixture.home())
        .env("HOME", fixture.home())
        .env("XDG_CONFIG_HOME", fixture.authmux_config_root())
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout is UTF-8"),
        "authentication status: 1 context\n"
    );
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr is UTF-8"),
        "provider status failed: GitHub credential is not stored in the system credential store\n"
    );
}

#[test]
fn github_exec_rejects_non_gh_children_before_provider_contact() {
    let fixture = GithubCliFixture::new("exec-non-gh");
    let bin_directory = fixture.configure_gh("success", "fictional-researcher", "keyring", 0);

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args(["exec", "--context", "github", "--", "git", "status"])
        .env("HOME", fixture.home())
        .env("XDG_CONFIG_HOME", fixture.authmux_config_root())
        .env("PATH", format!("{}:/usr/bin:/bin", bin_directory.display()))
        .output()
        .expect("authmux runs");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("stderr is UTF-8"),
        "GitHub execution supports only the gh CLI; raw Git authentication is not selected by GH_CONFIG_DIR\n"
    );
    assert!(
        !fixture.invocation().exists(),
        "unsupported child must not contact GitHub"
    );
}

struct GithubCliFixture {
    path: PathBuf,
}

impl GithubCliFixture {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "authmux-cli-github-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("fixture root is created");
        let fixture = Self { path };
        fixture.configure();
        fixture
    }

    fn home(&self) -> PathBuf {
        self.path.join("home")
    }

    fn authmux_config_root(&self) -> PathBuf {
        self.path.join("config")
    }

    fn github_config_dir(&self) -> PathBuf {
        self.home().join(".config/gh/research")
    }

    fn invocation(&self) -> PathBuf {
        self.path.join("gh-invocation")
    }

    fn configure(&self) {
        for directory in [
            self.home(),
            self.authmux_config_root().join("authmux"),
            self.github_config_dir(),
        ] {
            fs::create_dir_all(&directory).expect("fixture directory is created");
            set_mode(&directory, 0o700);
        }
        fs::write(
            self.authmux_config_root().join("authmux/config.toml"),
            format!(
                "version = 1\n\
                 [contexts.github]\n\
                 description = \"Fictional GitHub identity\"\n\
                 [contexts.github.providers.github]\n\
                 config_dir = \"{}\"\n\
                 hostname = \"github.com\"\n\
                 expected_login = \"fictional-researcher\"\n",
                self.github_config_dir().display()
            ),
        )
        .expect("authmux config is written");
    }

    fn configure_gh(
        &self,
        state: &str,
        login: &str,
        token_source: &str,
        exit_code: i32,
    ) -> PathBuf {
        let bin_directory = self.path.join("bin");
        fs::create_dir_all(&bin_directory).expect("bin directory is created");
        let executable = bin_directory.join("gh");
        fs::write(
            &executable,
            format!(
                "#!/bin/sh\n\
                 printf 'argv=' > '{}'\n\
                 first=1\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$first\" -eq 0 ]; then printf '|' >> '{}'; fi\n\
                   printf '%s' \"$arg\" >> '{}'\n\
                   first=0\n\
                 done\n\
                 printf '\\nGH_CONFIG_DIR=%s\\n' \"${{GH_CONFIG_DIR:-absent}}\" >> '{}'\n\
                 printf 'GH_TOKEN=%s\\n' \"${{GH_TOKEN:-absent}}\" >> '{}'\n\
                 printf '%s\\n' '{{\"hosts\":{{\"github.com\":[{{\"state\":\"{state}\",\"active\":true,\"host\":\"github.com\",\"login\":\"{login}\",\"tokenSource\":\"{token_source}\",\"scopes\":\"repo\",\"gitProtocol\":\"ssh\"}}]}}}}'\n\
                 exit {exit_code}\n",
                self.invocation().display(),
                self.invocation().display(),
                self.invocation().display(),
                self.invocation().display(),
                self.invocation().display(),
            ),
        )
        .expect("fictional gh is written");
        set_mode(&executable, 0o700);
        bin_directory
    }

    fn configure_gh_missing_host(&self) -> PathBuf {
        let bin_directory = self.path.join("bin");
        fs::create_dir_all(&bin_directory).expect("bin directory is created");
        let executable = bin_directory.join("gh");
        fs::write(
            &executable,
            format!(
                "#!/bin/sh\n\
                 if [ \"$1 $2\" = \"auth status\" ]; then\n\
                   printf '%s\\n' '{{\"hosts\":{{}}}}'\n\
                   exit 0\n\
                 fi\n\
                 touch '{}'\n\
                 exit 0\n",
                self.path.join("child-ran").display()
            ),
        )
        .expect("fictional gh is written");
        set_mode(&executable, 0o700);
        bin_directory
    }

    fn configure_gh_login(&self) -> PathBuf {
        let bin_directory = self.path.join("bin");
        fs::create_dir_all(&bin_directory).expect("bin directory is created");
        let executable = bin_directory.join("gh");
        fs::write(
            &executable,
            "#!/bin/sh\n\
             if [ \"$1 $2\" = \"auth login\" ]; then\n\
               printf 'native login argv='\n\
               first=1\n\
               for arg in \"$@\"; do\n\
                 if [ \"$first\" -eq 0 ]; then printf '|'; fi\n\
                 printf '%s' \"$arg\"\n\
                 first=0\n\
               done\n\
               printf '\\nnative login GH_CONFIG_DIR=%s\\n' \"${GH_CONFIG_DIR:-absent}\"\n\
               printf 'native login GH_TOKEN=%s\\n' \"${GH_TOKEN:-absent}\"\n\
               exit 0\n\
             fi\n\
             if [ \"$1 $2\" = \"auth status\" ]; then\n\
               printf '%s\\n' '{\"hosts\":{\"github.com\":[{\"state\":\"success\",\"active\":true,\"host\":\"github.com\",\"login\":\"fictional-researcher\",\"tokenSource\":\"keyring\"}]}}'\n\
               exit 0\n\
             fi\n\
             exit 97\n",
        )
        .expect("fictional gh is written");
        set_mode(&executable, 0o700);
        bin_directory
    }

    fn configure_gh_exec(&self) -> PathBuf {
        let bin_directory = self.path.join("bin");
        fs::create_dir_all(&bin_directory).expect("bin directory is created");
        let executable = bin_directory.join("gh");
        fs::write(
            &executable,
            "#!/bin/sh\n\
             if [ \"$1 $2\" = \"auth status\" ]; then\n\
               printf '%s\\n' '{\"hosts\":{\"github.com\":[{\"state\":\"success\",\"active\":true,\"host\":\"github.com\",\"login\":\"fictional-researcher\",\"tokenSource\":\"keyring\"}]}}'\n\
               exit 0\n\
             fi\n\
             printf 'child argv='\n\
             first=1\n\
             for arg in \"$@\"; do\n\
               if [ \"$first\" -eq 0 ]; then printf '|'; fi\n\
               printf '%s' \"$arg\"\n\
               first=0\n\
             done\n\
             printf '\\nchild GH_CONFIG_DIR=%s\\n' \"${GH_CONFIG_DIR:-absent}\"\n\
             printf 'child GH_HOST=%s\\n' \"${GH_HOST:-absent}\"\n\
             printf 'child GH_PROMPT_DISABLED=%s\\n' \"${GH_PROMPT_DISABLED:-absent}\"\n\
             printf 'child GH_TOKEN=%s\\n' \"${GH_TOKEN:-absent}\"\n\
             exit 0\n",
        )
        .expect("fictional gh is written");
        set_mode(&executable, 0o700);
        bin_directory
    }

    fn configure_gh_doctor(&self) -> PathBuf {
        let bin_directory = self.path.join("bin");
        fs::create_dir_all(&bin_directory).expect("bin directory is created");
        let executable = bin_directory.join("gh");
        fs::write(
            &executable,
            "#!/bin/sh\n\
             if [ \"$1\" = \"--version\" ]; then\n\
               printf 'gh version 2.96.0 (fictional)\\n'\n\
               exit 0\n\
             fi\n\
             exit 97\n",
        )
        .expect("fictional gh is written");
        set_mode(&executable, 0o700);
        bin_directory
    }
}

impl Drop for GithubCliFixture {
    fn drop(&mut self) {
        match fs::remove_dir_all(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("fixture cleanup failed: {error}"),
        }
    }
}

fn set_mode(path: &Path, mode: u32) {
    let mut permissions = fs::metadata(path)
        .expect("fixture metadata is readable")
        .permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions).expect("fixture permissions are set");
}

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn exec_refuses_a_fictional_aws_account_mismatch() {
    let fixture = FixtureDirectory::new("mismatch");
    let bin_directory = fixture.configure_aws("222222222222");

    let marker = fixture.path.join("child-ran");
    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args([
            "exec",
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
fn exec_runs_a_matching_context_with_the_child_exit_code() {
    let fixture = FixtureDirectory::new("matching");
    let bin_directory = fixture.configure_aws("111111111111");

    let output = Command::new(env!("CARGO_BIN_EXE_authmux"))
        .args([
            "exec",
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
                 if [ \"$1 $2 $3 $4 $5 $6 $7\" = \"sts get-caller-identity --query Account --output text --no-cli-pager\" ]; then\n\
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

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use authmux::{
    ExecutionSelection, ProbeOutput, ProbePolicy, ProbeRunner, ProviderFailure, SshTransportReuse,
    SshTransportStatus, UserConfig,
};

struct ControlCheckFixture {
    output: ProbeOutput,
}

impl ProbeRunner for ControlCheckFixture {
    fn probe(
        &self,
        command: &authmux::CommandSpec,
        selection: &ExecutionSelection,
        policy: ProbePolicy,
    ) -> Result<ProbeOutput, ProviderFailure> {
        assert_eq!(command.program(), "ssh");
        assert_eq!(command.arguments()[0], "-F");
        assert_eq!(command.arguments()[1], "/dev/null");
        assert_eq!(command.arguments()[2], "-S");
        assert_eq!(
            command.arguments()[4..],
            ["-O", "check", "authmux-local-status"]
        );
        assert!(selection.environment().is_empty());
        assert_eq!(policy.timeout(), Duration::from_secs(2));
        assert_eq!(policy.output_limit(), 4_096);
        Ok(self.output.clone())
    }
}

#[test]
fn active_control_socket_is_local_transport_evidence_only() {
    let fixture = StatusFixture::new("active");
    let ssh_directory = fixture.ssh_directory();
    let control_path = ssh_directory.join("empire.sock");
    let _listener = UnixListener::bind(&control_path).expect("fixture control socket is created");
    set_mode(&control_path, 0o600);
    let profile = StatusFixture::profile(&control_path);
    let status = SshTransportStatus::new(
        ControlCheckFixture {
            output: ProbeOutput::exited(0, b"Master running (pid=1234)\n", b""),
        },
        &ssh_directory,
    );

    let observation = status
        .observe(&profile)
        .expect("protected active socket is observable");

    assert_eq!(observation.transport_reuse(), SshTransportReuse::Active);
    assert!(!observation.provider_contacted());
}

#[test]
fn absent_control_socket_reports_inactive_without_a_session_claim() {
    let fixture = StatusFixture::new("inactive");
    let ssh_directory = fixture.ssh_directory();
    let control_path = ssh_directory.join("missing.sock");
    let profile = StatusFixture::profile(&control_path);
    let status = SshTransportStatus::new(
        ControlCheckFixture {
            output: ProbeOutput::exited(0, b"unused sensitive output", b""),
        },
        &ssh_directory,
    );

    let observation = status
        .observe(&profile)
        .expect("an absent protected socket is observable");

    assert_eq!(observation.transport_reuse(), SshTransportReuse::Inactive);
    assert!(!observation.provider_contacted());
}

#[test]
fn rejected_control_check_output_becomes_unknown_without_retaining_native_text() {
    let fixture = StatusFixture::new("unknown");
    let ssh_directory = fixture.ssh_directory();
    let control_path = ssh_directory.join("empire.sock");
    let _listener = UnixListener::bind(&control_path).expect("fixture control socket is created");
    set_mode(&control_path, 0o600);
    let profile = StatusFixture::profile(&control_path);
    let seeded_output = b"Master rejected ghp_fictional_sensitive_output";
    let status = SshTransportStatus::new(
        ControlCheckFixture {
            output: ProbeOutput::exited(255, b"", seeded_output),
        },
        &ssh_directory,
    );

    let observation = status
        .observe(&profile)
        .expect("a rejected local check remains status data");

    assert_eq!(observation.transport_reuse(), SshTransportReuse::Unknown);
    assert!(!format!("{observation:?}").contains("ghp_fictional_sensitive_output"));
}

struct StatusFixture {
    path: PathBuf,
}

impl StatusFixture {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let path = PathBuf::from("/private/tmp").join(format!(
            "amux-st-{label}-{}-{}",
            std::process::id(),
            nonce % 1_000_000_000
        ));
        fs::create_dir(&path).expect("fixture directory is created");
        Self { path }
    }

    fn ssh_directory(&self) -> PathBuf {
        let directory = self.path.join(".ssh");
        fs::create_dir(&directory).expect("SSH directory is created");
        set_mode(&directory, 0o700);
        directory
    }

    fn profile(control_path: &Path) -> authmux::SshProviderDefinition {
        let source = format!(
            "version = 1\n\
             [contexts.empire.providers.ssh]\n\
             host_alias = \"empire-alpha\"\n\
             expected_remote_principal = \"researcher@example.invalid\"\n\
             control_path = \"{}\"\n",
            control_path.display()
        );
        UserConfig::parse(&source)
            .expect("fixture config is valid")
            .resolve_context_definition("empire")
            .expect("fixture context resolves")
            .ssh()
            .expect("fixture SSH profile resolves")
            .clone()
    }
}

impl Drop for StatusFixture {
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

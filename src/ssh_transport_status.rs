use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::{
    CommandSpec, ExecutionSelection, ProbePolicy, ProbeRunner, ProviderFailure,
    SshProviderDefinition,
};

pub struct SshTransportStatus<R> {
    runner: R,
    ssh_directory: PathBuf,
}

impl<R> SshTransportStatus<R> {
    #[must_use]
    pub fn new(runner: R, ssh_directory: impl Into<PathBuf>) -> Self {
        Self {
            runner,
            ssh_directory: ssh_directory.into(),
        }
    }
}

impl<R> SshTransportStatus<R>
where
    R: ProbeRunner,
{
    /// Observes only a protected, explicitly configured local OpenSSH control
    /// socket. It does not evaluate SSH configuration or contact a provider.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure when the profile has no control path or the
    /// path falls outside the allowed SSH directory.
    pub fn observe(
        &self,
        profile: &SshProviderDefinition,
    ) -> Result<SshTransportObservation, ProviderFailure> {
        let control_path = profile.control_path().ok_or_else(|| {
            ProviderFailure::sanitized("SSH transport status requires an explicit control_path")
        })?;
        if control_path == self.ssh_directory || !control_path.starts_with(&self.ssh_directory) {
            return Err(ProviderFailure::sanitized(
                "SSH control path is outside the allowed user SSH directory",
            ));
        }

        let transport_reuse = match inspect_control_socket(control_path, &self.ssh_directory) {
            SocketInspection::Inactive => SshTransportReuse::Inactive,
            SocketInspection::Unknown => SshTransportReuse::Unknown,
            SocketInspection::Ready => self.probe_control_socket(control_path),
        };
        Ok(SshTransportObservation {
            observed_at: SystemTime::now(),
            transport_reuse,
        })
    }

    fn probe_control_socket(&self, control_path: &Path) -> SshTransportReuse {
        let command = CommandSpec::new(
            "ssh",
            [
                OsString::from("-F"),
                OsString::from("/dev/null"),
                OsString::from("-S"),
                control_path.as_os_str().to_owned(),
                OsString::from("-O"),
                OsString::from("check"),
                OsString::from("authmux-local-status"),
            ],
        );
        let Ok(command) = command else {
            return SshTransportReuse::Unknown;
        };
        match self.runner.probe(
            &command,
            &ExecutionSelection::none(),
            ProbePolicy::bounded(Duration::from_secs(2), 4_096),
        ) {
            Ok(output) if output.exit_code() == 0 && !output.was_truncated() => {
                SshTransportReuse::Active
            }
            Ok(_) | Err(_) => SshTransportReuse::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SshTransportReuse {
    Active,
    Inactive,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshTransportObservation {
    observed_at: SystemTime,
    transport_reuse: SshTransportReuse,
}

impl SshTransportObservation {
    #[must_use]
    pub fn observed_at(&self) -> SystemTime {
        self.observed_at
    }

    #[must_use]
    pub fn transport_reuse(&self) -> SshTransportReuse {
        self.transport_reuse
    }

    #[must_use]
    pub const fn provider_contacted(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SocketInspection {
    Ready,
    Inactive,
    Unknown,
}

fn inspect_control_socket(control_path: &Path, ssh_directory: &Path) -> SocketInspection {
    let root = match fs::symlink_metadata(ssh_directory) {
        Ok(metadata) if protected_directory(&metadata, None) => metadata,
        Ok(_) | Err(_) => return SocketInspection::Unknown,
    };
    let owner = root.uid();
    let Some(parent) = control_path.parent() else {
        return SocketInspection::Unknown;
    };
    let Ok(relative_parent) = parent.strip_prefix(ssh_directory) else {
        return SocketInspection::Unknown;
    };
    let mut current = ssh_directory.to_path_buf();
    for component in relative_parent.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if protected_directory(&metadata, Some(owner)) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return SocketInspection::Inactive;
            }
            Ok(_) | Err(_) => return SocketInspection::Unknown,
        }
    }

    match fs::symlink_metadata(control_path) {
        Ok(metadata) if metadata.file_type().is_socket() && metadata.uid() == owner => {
            SocketInspection::Ready
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => SocketInspection::Inactive,
        Ok(_) | Err(_) => SocketInspection::Unknown,
    }
}

fn protected_directory(metadata: &fs::Metadata, owner: Option<u32>) -> bool {
    metadata.file_type().is_dir()
        && owner.is_none_or(|owner| metadata.uid() == owner)
        && metadata.mode() & 0o022 == 0
}

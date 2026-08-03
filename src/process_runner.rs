use std::ffi::OsString;
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use wait_timeout::ChildExt;

use crate::{
    CommandSpec, DomainFailure, ExecutionFailure, ExecutionOutcome, ExecutionSelection,
    ProcessRunner, ProviderFailure,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbePolicy {
    timeout: Duration,
    output_limit: usize,
}

impl ProbePolicy {
    #[must_use]
    pub fn bounded(timeout: Duration, output_limit: usize) -> Self {
        Self {
            timeout,
            output_limit,
        }
    }

    #[must_use]
    pub fn timeout(self) -> Duration {
        self.timeout
    }

    #[must_use]
    pub fn output_limit(self) -> usize {
        self.output_limit
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeOutput {
    exit_code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    truncated: bool,
}

impl ProbeOutput {
    #[must_use]
    pub fn exited(exit_code: i32, stdout: &[u8], stderr: &[u8]) -> Self {
        Self {
            exit_code,
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
            truncated: false,
        }
    }

    fn bounded(exit_code: i32, stdout: Vec<u8>, stderr: Vec<u8>, truncated: bool) -> Self {
        Self {
            exit_code,
            stdout,
            stderr,
            truncated,
        }
    }

    #[must_use]
    pub fn exit_code(&self) -> i32 {
        self.exit_code
    }

    #[must_use]
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    #[must_use]
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    #[must_use]
    pub fn was_truncated(&self) -> bool {
        self.truncated
    }
}

pub trait ProbeRunner {
    /// Runs a bounded, read-only provider command and captures capped output.
    ///
    /// # Errors
    ///
    /// Returns a sanitized provider failure on spawn, timeout, wait, or output
    /// reader failure.
    fn probe(
        &self,
        command: &CommandSpec,
        selection: &ExecutionSelection,
        policy: ProbePolicy,
    ) -> Result<ProbeOutput, ProviderFailure>;
}

impl<R> ProbeRunner for &R
where
    R: ProbeRunner + ?Sized,
{
    fn probe(
        &self,
        command: &CommandSpec,
        selection: &ExecutionSelection,
        policy: ProbePolicy,
    ) -> Result<ProbeOutput, ProviderFailure> {
        (**self).probe(command, selection, policy)
    }
}

pub struct SecureProcessRunner {
    inherited_environment: Vec<OsString>,
}

impl SecureProcessRunner {
    /// Creates a runner with a user-owned environment inheritance allowlist.
    ///
    /// # Errors
    ///
    /// Returns a domain failure when an allowlisted variable name is empty.
    pub fn new(inherited_environment: &[&str]) -> Result<Self, DomainFailure> {
        let inherited_environment = inherited_environment
            .iter()
            .map(OsString::from)
            .collect::<Vec<_>>();

        if inherited_environment
            .iter()
            .any(|name| name.as_os_str().is_empty())
        {
            return Err(DomainFailure::public(
                "inherited environment names cannot be empty",
            ));
        }

        Ok(Self {
            inherited_environment,
        })
    }
}

impl ProcessRunner for SecureProcessRunner {
    fn run(
        &self,
        command: &CommandSpec,
        selection: &ExecutionSelection,
    ) -> Result<ExecutionOutcome, ExecutionFailure> {
        let status = self.command(command, selection).status().map_err(|error| {
            ExecutionFailure::Process(format!("could not start child process ({})", error.kind()))
        })?;

        if let Some(code) = status.code() {
            return Ok(ExecutionOutcome::exited(code));
        }

        #[cfg(unix)]
        if let Some(signal) = status.signal() {
            return Ok(ExecutionOutcome::signaled(signal));
        }

        Err(ExecutionFailure::Process(
            "child process ended without an exit code or signal".to_owned(),
        ))
    }
}

impl ProbeRunner for SecureProcessRunner {
    fn probe(
        &self,
        command: &CommandSpec,
        selection: &ExecutionSelection,
        policy: ProbePolicy,
    ) -> Result<ProbeOutput, ProviderFailure> {
        let mut process = self.command(command, selection);
        process.stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = process.spawn().map_err(|error| {
            ProviderFailure::sanitized(format!("could not start provider probe ({})", error.kind()))
        })?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ProviderFailure::sanitized("provider probe stdout was unavailable"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| ProviderFailure::sanitized("provider probe stderr was unavailable"))?;
        let stdout_reader = read_bounded(stdout, policy.output_limit());
        let stderr_reader = read_bounded(stderr, policy.output_limit());

        let status = child.wait_timeout(policy.timeout()).map_err(|error| {
            ProviderFailure::sanitized(format!(
                "could not wait for provider probe ({})",
                error.kind()
            ))
        })?;

        let Some(status) = status else {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(ProviderFailure::sanitized(format!(
                "provider probe timed out after {} ms",
                policy.timeout().as_millis()
            )));
        };

        let (stdout, stdout_truncated) = join_reader(stdout_reader)?;
        let (stderr, stderr_truncated) = join_reader(stderr_reader)?;
        let exit_code = status.code().unwrap_or(-1);

        Ok(ProbeOutput::bounded(
            exit_code,
            stdout,
            stderr,
            stdout_truncated || stderr_truncated,
        ))
    }
}

impl SecureProcessRunner {
    fn command(&self, command: &CommandSpec, selection: &ExecutionSelection) -> Command {
        let mut child = Command::new(command.program());
        child.args(command.arguments()).env_clear();

        for name in &self.inherited_environment {
            if let Some(value) = std::env::var_os(name) {
                child.env(name, value);
            }
        }

        for (name, value) in selection.environment() {
            child.env(name, value);
        }

        child
    }
}

type ReaderResult = Result<(Vec<u8>, bool), io::Error>;

fn read_bounded<R>(mut reader: R, limit: usize) -> thread::JoinHandle<ReaderResult>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut bytes = Vec::with_capacity(limit.min(8_192));
        let mut chunk = [0_u8; 4_096];
        loop {
            let count = reader.read(&mut chunk)?;
            if count == 0 {
                return Ok((bytes, false));
            }

            let remaining = limit.saturating_sub(bytes.len());
            let accepted = count.min(remaining);
            bytes.extend_from_slice(&chunk[..accepted]);
            if accepted < count {
                return Ok((bytes, true));
            }
        }
    })
}

fn join_reader(
    reader: thread::JoinHandle<ReaderResult>,
) -> Result<(Vec<u8>, bool), ProviderFailure> {
    reader
        .join()
        .map_err(|_| ProviderFailure::sanitized("provider probe output reader failed"))?
        .map_err(|error| {
            ProviderFailure::sanitized(format!(
                "could not read provider probe output ({})",
                error.kind()
            ))
        })
}

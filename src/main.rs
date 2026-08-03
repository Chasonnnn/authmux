use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process;

use authmux::{
    AwsAdapter, CommandSpec, ContextEngine, ExecutionFailure, ProjectBinding, SecureProcessRunner,
    UserConfig,
};

fn main() {
    process::exit(run());
}

fn run() -> i32 {
    match parse_exec(env::args_os().skip(1).collect()) {
        Ok((selection, command)) => execute(selection, &command),
        Err(message) => {
            eprintln!("{message}");
            2
        }
    }
}

fn execute(selection: ContextSelection, command: &CommandSpec) -> i32 {
    let context_name = match selection {
        ContextSelection::Explicit(context_name) => context_name,
        ContextSelection::ProjectBound => {
            let working_directory = match env::current_dir() {
                Ok(directory) => directory,
                Err(error) => {
                    eprintln!("could not resolve working directory ({:?})", error.kind());
                    return 2;
                }
            };
            match ProjectBinding::discover(&working_directory) {
                Ok(binding) => binding.context_name().to_owned(),
                Err(failure) => {
                    eprintln!("{failure}");
                    return 2;
                }
            }
        }
    };
    let config_text = match fs::read_to_string(user_config_path()) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("could not read user configuration ({})", error.kind());
            return 2;
        }
    };
    let context = match UserConfig::parse(&config_text)
        .and_then(|config| config.resolve_context(&context_name))
    {
        Ok(context) => context,
        Err(failure) => {
            eprintln!("{failure}");
            return 2;
        }
    };

    let inherited = ["PATH", "HOME", "LANG", "LC_ALL", "TERM"];
    let probe_runner = match SecureProcessRunner::new(&inherited) {
        Ok(runner) => runner,
        Err(failure) => {
            eprintln!("{failure}");
            return 2;
        }
    };
    let child_runner = match SecureProcessRunner::new(&inherited) {
        Ok(runner) => runner,
        Err(failure) => {
            eprintln!("{failure}");
            return 2;
        }
    };
    let engine = ContextEngine::new(AwsAdapter::new(probe_runner), child_runner);

    match engine.execute(&context, command) {
        Ok(outcome) => outcome.exit_code(),
        Err(failure) => {
            eprintln!("{failure}");
            exit_code(&failure)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ContextSelection {
    Explicit(String),
    ProjectBound,
}

fn parse_exec(arguments: Vec<OsString>) -> Result<(ContextSelection, CommandSpec), String> {
    const USAGE: &str = "usage: authmux exec [--context <context>] -- <program> [args...]";
    if arguments.first().and_then(|arg| arg.to_str()) != Some("exec") {
        return Err(USAGE.to_owned());
    }

    let (selection, delimiter_index) = match arguments.get(1).and_then(|arg| arg.to_str()) {
        Some("--") => (ContextSelection::ProjectBound, 1),
        Some("--context") => {
            let context_name = arguments
                .get(2)
                .and_then(|argument| argument.to_str())
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "exec requires a Unicode context name".to_owned())?
                .to_owned();
            (ContextSelection::Explicit(context_name), 3)
        }
        _ => return Err(USAGE.to_owned()),
    };

    if arguments.get(delimiter_index).and_then(|arg| arg.to_str()) != Some("--") {
        return Err("exec requires `--` before the child command".to_owned());
    }
    let program = arguments
        .get(delimiter_index + 1)
        .cloned()
        .ok_or_else(|| "exec requires a child program".to_owned())?;
    let command = CommandSpec::new(program, arguments.into_iter().skip(delimiter_index + 2))
        .map_err(|failure| failure.to_string())?;

    Ok((selection, command))
}

fn user_config_path() -> PathBuf {
    if let Some(directory) = env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(directory).join("authmux").join("config.toml");
    }

    env::var_os("HOME").map_or_else(
        || PathBuf::from(".config/authmux/config.toml"),
        |home| PathBuf::from(home).join(".config/authmux/config.toml"),
    )
}

fn exit_code(failure: &ExecutionFailure) -> i32 {
    match failure {
        ExecutionFailure::IdentityMismatch { .. } => 3,
        ExecutionFailure::SessionUnusable { .. }
        | ExecutionFailure::SessionIndeterminate { .. } => 4,
        ExecutionFailure::Provider(_) => 5,
        ExecutionFailure::Process(_) => 126,
    }
}

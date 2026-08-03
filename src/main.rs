use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process;

use authmux::{
    AwsAdapter, CommandSpec, ContextEngine, ExecutionFailure, SecureProcessRunner, UserConfig,
};

fn main() {
    process::exit(run());
}

fn run() -> i32 {
    match parse_exec(env::args_os().skip(1).collect()) {
        Ok((context_name, command)) => execute(&context_name, &command),
        Err(message) => {
            eprintln!("{message}");
            2
        }
    }
}

fn execute(context_name: &str, command: &CommandSpec) -> i32 {
    let config_text = match fs::read_to_string(user_config_path()) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("could not read user configuration ({})", error.kind());
            return 2;
        }
    };
    let context = match UserConfig::parse(&config_text)
        .and_then(|config| config.resolve_context(context_name))
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

fn parse_exec(arguments: Vec<OsString>) -> Result<(String, CommandSpec), String> {
    if arguments.first().and_then(|arg| arg.to_str()) != Some("exec") {
        return Err("usage: authmux exec <context> -- <program> [args...]".to_owned());
    }
    let context = arguments
        .get(1)
        .and_then(|argument| argument.to_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "exec requires a Unicode context name".to_owned())?
        .to_owned();
    if arguments.get(2).and_then(|arg| arg.to_str()) != Some("--") {
        return Err("exec requires `--` before the child command".to_owned());
    }
    let program = arguments
        .get(3)
        .cloned()
        .ok_or_else(|| "exec requires a child program".to_owned())?;
    let command = CommandSpec::new(program, arguments.into_iter().skip(4))
        .map_err(|failure| failure.to_string())?;

    Ok((context, command))
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

use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::process;

#[cfg(unix)]
use nix::sys::signal::{Signal, kill};
#[cfg(unix)]
use nix::unistd::Pid;

use authmux::{
    AwsAdapter, AwsDoctor, AwsLocalMetadataAdapter, CommandSpec, ContextDefinition, ContextEngine,
    ContextListReport, DoctorOutcome, DoctorReport, ExecutionFailure, ProjectBinding,
    SecureProcessRunner, StatusEngine, StatusReport, UserConfig,
};

fn main() {
    process::exit(run());
}

fn run() -> i32 {
    match parse_command(env::args_os().skip(1).collect()) {
        Ok(CliCommand::Exec { selection, command }) => execute(selection, &command),
        Ok(CliCommand::ContextShow { selection }) => show_context(selection),
        Ok(CliCommand::ContextList { format }) => show_context_list(format),
        Ok(CliCommand::Status { selection, format }) => show_status(selection, format),
        Ok(CliCommand::Doctor { selection, format }) => show_doctor(selection, format),
        Err(message) => {
            eprintln!("{message}");
            2
        }
    }
}

fn execute(selection: ContextSelection, command: &CommandSpec) -> i32 {
    let selection = match resolve_selection(selection) {
        Ok(selection) => selection,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };
    let (config, _) = match load_user_config() {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };
    let context = match config.resolve_context(&selection.context_name) {
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
        Ok(outcome) => match (outcome.exit_code(), outcome.signal()) {
            (Some(exit_code), None) => exit_code,
            (None, Some(signal)) => terminate_with_signal(signal),
            _ => 126,
        },
        Err(failure) => {
            eprintln!("{failure}");
            exit_code(&failure)
        }
    }
}

fn show_context(selection: ContextSelection) -> i32 {
    let selection = match resolve_selection(selection) {
        Ok(selection) => selection,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };
    let (config, definition_source) = match load_user_config() {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };
    let definition = match config.resolve_context_definition(&selection.context_name) {
        Ok(definition) => definition,
        Err(failure) => {
            eprintln!("{failure}");
            return 2;
        }
    };

    print_context(&selection, &definition, &definition_source);
    0
}

fn show_context_list(format: ReportFormat) -> i32 {
    let (config, _) = match load_user_config() {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };
    let definitions = match config.context_definitions() {
        Ok(definitions) => definitions,
        Err(failure) => {
            eprintln!("{failure}");
            return 2;
        }
    };
    let report = ContextListReport::new(&definitions);
    let rendered = match format {
        ReportFormat::Human => report.render_human(),
        ReportFormat::Json => match report.render_json() {
            Ok(json) => json,
            Err(failure) => {
                eprintln!("could not render context list: {failure}");
                return 5;
            }
        },
    };
    print!("{rendered}");
    0
}

fn show_status(selection: ContextSelection, format: ReportFormat) -> i32 {
    let selection = match resolve_selection(selection) {
        Ok(selection) => selection,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };
    let (config, _) = match load_user_config() {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };
    let context = match config.resolve_context(&selection.context_name) {
        Ok(context) => context,
        Err(failure) => {
            eprintln!("{failure}");
            return 2;
        }
    };
    let inherited = ["PATH", "HOME", "LANG", "LC_ALL", "TERM"];
    let runner = match SecureProcessRunner::new(&inherited) {
        Ok(runner) => runner,
        Err(failure) => {
            eprintln!("{failure}");
            return 2;
        }
    };
    let engine = StatusEngine::new(AwsLocalMetadataAdapter::new(runner));
    let observation = match engine.observe(&context) {
        Ok(observation) => observation,
        Err(failure) => {
            eprintln!("provider status failed: {failure}");
            return 5;
        }
    };

    let report = match StatusReport::local_aws(&context, &observation) {
        Ok(report) => report,
        Err(failure) => {
            eprintln!("could not render status: {failure}");
            return 5;
        }
    };
    let rendered = match format {
        ReportFormat::Human => report.render_human(),
        ReportFormat::Json => match report.render_json() {
            Ok(json) => json,
            Err(failure) => {
                eprintln!("could not render status: {failure}");
                return 5;
            }
        },
    };
    print!("{rendered}");
    0
}

fn show_doctor(selection: ContextSelection, format: ReportFormat) -> i32 {
    let selection = match resolve_selection(selection) {
        Ok(selection) => selection,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };
    let (config, _) = match load_user_config() {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };
    let context = match config.resolve_context(&selection.context_name) {
        Ok(context) => context,
        Err(failure) => {
            eprintln!("{failure}");
            return 2;
        }
    };
    let inherited = ["PATH", "HOME", "LANG", "LC_ALL", "TERM"];
    let version_runner = match SecureProcessRunner::new(&inherited) {
        Ok(runner) => runner,
        Err(failure) => {
            eprintln!("{failure}");
            return 2;
        }
    };
    let status_runner = match SecureProcessRunner::new(&inherited) {
        Ok(runner) => runner,
        Err(failure) => {
            eprintln!("{failure}");
            return 2;
        }
    };
    let result = AwsDoctor::new(version_runner, status_runner).diagnose(&context);
    let outcome = result.outcome();
    let report = DoctorReport::new(&result);
    let rendered = match format {
        ReportFormat::Human => report.render_human(),
        ReportFormat::Json => match report.render_json() {
            Ok(json) => json,
            Err(failure) => {
                eprintln!("could not render doctor report: {failure}");
                return 5;
            }
        },
    };
    print!("{rendered}");
    i32::from(outcome == DoctorOutcome::Fail)
}

fn print_context(
    selection: &ResolvedSelection,
    definition: &ContextDefinition,
    definition_source: &std::path::Path,
) {
    let context = definition.context();
    println!("context: {}", context.name());
    match &selection.source {
        SelectionSource::CommandLine => println!("selection: command line"),
        SelectionSource::ProjectBinding(source) => {
            println!("selection: project binding");
            println!("binding source: {}", render_path(source));
        }
    }
    println!(
        "description: {}",
        definition.description().unwrap_or("(none)")
    );
    println!("definition source: {}", render_path(definition_source));
    println!("aws profile: {}", context.provider_profile());
    println!("expected AWS account: {}", context.expected_account());
    println!("provider state: not observed");
}

fn render_path(path: &std::path::Path) -> String {
    let mut rendered = String::new();
    for character in path.to_string_lossy().chars() {
        if character.is_control()
            || matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            write!(rendered, "\\u{{{:x}}}", u32::from(character))
                .expect("writing to a String cannot fail");
        } else {
            rendered.push(character);
        }
    }
    rendered
}

#[cfg(unix)]
fn terminate_with_signal(signal_number: i32) -> i32 {
    if let Ok(signal) = Signal::try_from(signal_number) {
        let _ = kill(Pid::this(), signal);
    }

    128_i32.saturating_add(signal_number)
}

#[cfg(not(unix))]
fn terminate_with_signal(signal_number: i32) -> i32 {
    128_i32.saturating_add(signal_number)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ContextSelection {
    Explicit(String),
    ProjectBound,
}

enum CliCommand {
    Exec {
        selection: ContextSelection,
        command: CommandSpec,
    },
    ContextShow {
        selection: ContextSelection,
    },
    ContextList {
        format: ReportFormat,
    },
    Status {
        selection: ContextSelection,
        format: ReportFormat,
    },
    Doctor {
        selection: ContextSelection,
        format: ReportFormat,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReportFormat {
    Human,
    Json,
}

struct ResolvedSelection {
    context_name: String,
    source: SelectionSource,
}

enum SelectionSource {
    CommandLine,
    ProjectBinding(PathBuf),
}

fn parse_command(arguments: Vec<OsString>) -> Result<CliCommand, String> {
    match arguments.first().and_then(|argument| argument.to_str()) {
        Some("exec") => parse_exec(arguments)
            .map(|(selection, command)| CliCommand::Exec { selection, command }),
        Some("context") => parse_context_command(&arguments),
        Some("status") => parse_status(&arguments)
            .map(|(selection, format)| CliCommand::Status { selection, format }),
        Some("doctor") => parse_doctor(&arguments)
            .map(|(selection, format)| CliCommand::Doctor { selection, format }),
        _ => Err("usage: authmux <exec|context|doctor|status> ...".to_owned()),
    }
}

fn parse_context_command(arguments: &[OsString]) -> Result<CliCommand, String> {
    match arguments.get(1).and_then(|argument| argument.to_str()) {
        Some("show") => {
            parse_context_show(arguments).map(|selection| CliCommand::ContextShow { selection })
        }
        Some("list") => {
            parse_context_list(arguments).map(|format| CliCommand::ContextList { format })
        }
        _ => Err("usage: authmux context <list|show> ...".to_owned()),
    }
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

fn parse_context_show(arguments: &[OsString]) -> Result<ContextSelection, String> {
    const USAGE: &str = "usage: authmux context show [--context <context>]";
    if arguments.get(1).and_then(|argument| argument.to_str()) != Some("show") {
        return Err(USAGE.to_owned());
    }

    match arguments.len() {
        2 => Ok(ContextSelection::ProjectBound),
        4 if arguments.get(2).and_then(|argument| argument.to_str()) == Some("--context") => {
            let context_name = arguments
                .get(3)
                .and_then(|argument| argument.to_str())
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "context show requires a Unicode context name".to_owned())?;
            Ok(ContextSelection::Explicit(context_name.to_owned()))
        }
        _ => Err(USAGE.to_owned()),
    }
}

fn parse_context_list(arguments: &[OsString]) -> Result<ReportFormat, String> {
    const USAGE: &str = "usage: authmux context list [--json]";
    match arguments.len() {
        2 => Ok(ReportFormat::Human),
        3 if arguments.get(2).and_then(|argument| argument.to_str()) == Some("--json") => {
            Ok(ReportFormat::Json)
        }
        _ => Err(USAGE.to_owned()),
    }
}

fn parse_status(arguments: &[OsString]) -> Result<(ContextSelection, ReportFormat), String> {
    const USAGE: &str = "usage: authmux status [--context <context>] [--json]";
    let mut selection = None;
    let mut format = ReportFormat::Human;
    let mut index = 1;
    while index < arguments.len() {
        match arguments.get(index).and_then(|argument| argument.to_str()) {
            Some("--context") if selection.is_none() => {
                let context_name = arguments
                    .get(index + 1)
                    .and_then(|argument| argument.to_str())
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| "status requires a Unicode context name".to_owned())?;
                selection = Some(ContextSelection::Explicit(context_name.to_owned()));
                index += 2;
            }
            Some("--json") if format == ReportFormat::Human => {
                format = ReportFormat::Json;
                index += 1;
            }
            _ => return Err(USAGE.to_owned()),
        }
    }

    Ok((selection.unwrap_or(ContextSelection::ProjectBound), format))
}

fn parse_doctor(arguments: &[OsString]) -> Result<(ContextSelection, ReportFormat), String> {
    const USAGE: &str = "usage: authmux doctor [--context <context>] [--json]";
    let mut selection = None;
    let mut format = ReportFormat::Human;
    let mut index = 1;
    while index < arguments.len() {
        match arguments.get(index).and_then(|argument| argument.to_str()) {
            Some("--context") if selection.is_none() => {
                let context_name = arguments
                    .get(index + 1)
                    .and_then(|argument| argument.to_str())
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| "doctor requires a Unicode context name".to_owned())?;
                selection = Some(ContextSelection::Explicit(context_name.to_owned()));
                index += 2;
            }
            Some("--json") if format == ReportFormat::Human => {
                format = ReportFormat::Json;
                index += 1;
            }
            _ => return Err(USAGE.to_owned()),
        }
    }

    Ok((selection.unwrap_or(ContextSelection::ProjectBound), format))
}

fn resolve_selection(selection: ContextSelection) -> Result<ResolvedSelection, String> {
    match selection {
        ContextSelection::Explicit(context_name) => Ok(ResolvedSelection {
            context_name,
            source: SelectionSource::CommandLine,
        }),
        ContextSelection::ProjectBound => {
            let working_directory = env::current_dir().map_err(|error| {
                format!("could not resolve working directory ({:?})", error.kind())
            })?;
            let binding = ProjectBinding::discover(&working_directory)
                .map_err(|failure| failure.to_string())?;
            Ok(ResolvedSelection {
                context_name: binding.context_name().to_owned(),
                source: SelectionSource::ProjectBinding(binding.source().to_path_buf()),
            })
        }
    }
}

fn load_user_config() -> Result<(UserConfig, PathBuf), String> {
    let source = user_config_path();
    let config_text = fs::read_to_string(&source)
        .map_err(|error| format!("could not read user configuration ({:?})", error.kind()))?;
    let config = UserConfig::parse(&config_text).map_err(|failure| failure.to_string())?;
    let source = fs::canonicalize(&source).unwrap_or(source);
    Ok((config, source))
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

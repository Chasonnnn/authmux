use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::PathBuf;
use std::process;

#[cfg(unix)]
use nix::sys::signal::{Signal, kill};
#[cfg(unix)]
use nix::unistd::Pid;

use authmux::{
    AwsAdapter, AwsDoctor, AwsLocalMetadataAdapter, AwsLoginPlan, AwsLoginPlanner, CommandSpec,
    ContextDefinition, ContextEngine, ContextListReport, DoctorOutcome, DoctorReport,
    ExecutionContextResolver, ExecutionFailure, ExecutionSelection, GcpDoctor, GcpExecutionFailure,
    GcpExecutionGuard, GcpLocalStatus, GcpLoginPlan, ProcessRunner, ProjectBinding,
    SecureProcessRunner, SshDoctor, SshTransportObservation, SshTransportReuse, SshTransportStatus,
    StatusEngine, StatusReport, UserConfig,
};

fn main() {
    process::exit(run());
}

fn run() -> i32 {
    match parse_command(env::args_os().skip(1).collect()) {
        Ok(CliCommand::Exec { selection, command }) => execute(selection, &command),
        Ok(CliCommand::ContextShow { selection }) => show_context(selection),
        Ok(CliCommand::ContextList { format }) => show_context_list(format),
        Ok(CliCommand::Status {
            selection,
            provider,
            format,
            require_active_transport,
        }) => show_status(selection, provider, format, require_active_transport),
        Ok(CliCommand::Login {
            selection,
            provider,
        }) => login(selection, provider),
        Ok(CliCommand::Doctor {
            selection,
            provider,
            format,
        }) => show_doctor(selection, provider, format),
        Err(message) => {
            eprintln!("{message}");
            2
        }
    }
}

fn login(selection: ContextSelection, provider: Option<ProviderSelection>) -> i32 {
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
    let definition = match config.resolve_context_definition(&selection.context_name) {
        Ok(definition) => definition,
        Err(failure) => {
            eprintln!("{failure}");
            return 2;
        }
    };
    let provider = match resolve_login_provider(&definition, provider) {
        Ok(provider) => provider,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };

    match provider {
        ProviderSelection::Aws => login_aws(&definition),
        ProviderSelection::Ssh => login_ssh(&definition),
        ProviderSelection::Gcp => login_gcp(&definition),
    }
}

fn login_aws(definition: &ContextDefinition) -> i32 {
    let Some(context) = definition.aws() else {
        eprintln!("AWS Provider Profile is not configured");
        return 2;
    };
    let planning_runner = match SecureProcessRunner::for_authmux() {
        Ok(runner) => runner,
        Err(failure) => {
            eprintln!("{failure}");
            return 2;
        }
    };
    let plan = match AwsLoginPlanner::new(planning_runner).plan(context) {
        Ok(plan) => plan,
        Err(failure) => {
            eprintln!("{failure}");
            return failure.exit_code();
        }
    };

    if let Err(error) = display_aws_login_preview(definition, &plan) {
        eprintln!("could not display AWS login preview ({})", error.kind());
        return 5;
    }

    let Ok((current_config, _)) = load_user_config() else {
        eprintln!("refusing AWS login: authentication context could not be re-resolved");
        return 6;
    };
    let Ok(current_definition) = current_config.resolve_context_definition(definition.name())
    else {
        eprintln!("refusing AWS login: authentication context could not be re-resolved");
        return 6;
    };
    if let Err(failure) = AwsLoginPlan::ensure_context_unchanged(definition, &current_definition) {
        eprintln!("{failure}");
        return failure.exit_code();
    }
    let Some(current_context) = current_definition.aws() else {
        eprintln!("refusing AWS login: authentication context could not be re-resolved");
        return 6;
    };
    let current_planning_runner = match SecureProcessRunner::for_authmux() {
        Ok(runner) => runner,
        Err(failure) => {
            eprintln!("{failure}");
            return 2;
        }
    };
    let current_plan = match AwsLoginPlanner::new(current_planning_runner).plan(current_context) {
        Ok(plan) => plan,
        Err(failure) => {
            eprintln!("{failure}");
            return failure.exit_code();
        }
    };
    if plan != current_plan {
        let failure = authmux::AwsLoginFailure::PlanChanged;
        eprintln!("{failure}");
        return failure.exit_code();
    }

    run_aws_login(&plan)
}

fn display_aws_login_preview(
    definition: &ContextDefinition,
    plan: &AwsLoginPlan,
) -> Result<(), std::io::Error> {
    println!("login: {}", definition.name());
    println!("provider: aws");
    println!("AWS Provider Profile: {}", plan.provider_profile());
    println!("expected AWS account: {}", plan.expected_account());
    println!("reauthentication mode: {}", plan.mode());
    println!("native login profile: {}", plan.login_profile());
    let native_arguments = plan
        .command()
        .arguments()
        .iter()
        .map(|argument| argument.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    println!("native command: aws {native_arguments}");
    std::io::stdout().flush()
}

fn run_aws_login(plan: &AwsLoginPlan) -> i32 {
    let runner = match SecureProcessRunner::for_authmux() {
        Ok(runner) => runner,
        Err(failure) => {
            eprintln!("{failure}");
            return 2;
        }
    };
    match runner.run(plan.command(), plan.selection()) {
        Ok(outcome) => match (outcome.exit_code(), outcome.signal()) {
            (Some(0), None) => {
                println!(
                    "result: native AWS login command exited successfully; live session usability remains unverified"
                );
                0
            }
            (Some(code), None) => {
                eprintln!("native AWS login command exited with status {code}");
                code
            }
            (None, Some(signal)) => terminate_with_signal(signal),
            _ => {
                eprintln!("native AWS login command ended without an exit code or signal");
                5
            }
        },
        Err(failure) => {
            eprintln!("{failure}");
            exit_code(&failure)
        }
    }
}

fn login_gcp(definition: &ContextDefinition) -> i32 {
    let Some(profile) = definition.gcp() else {
        eprintln!("GCP Provider Profile is not configured");
        return 2;
    };
    let plan = match GcpLoginPlan::new(profile) {
        Ok(plan) => plan,
        Err(failure) => {
            eprintln!("{failure}");
            return failure.exit_code();
        }
    };

    println!("login: {}", definition.name());
    println!("provider: gcp");
    println!("credential plane: gcloud_cli");
    println!("gcloud configuration: {}", plan.configuration());
    println!("expected gcloud identity: {}", plan.expected_identity());
    println!("login account: {}", plan.login_account());
    println!(
        "native command: gcloud auth login {} --brief --force",
        plan.login_account()
    );
    if let Err(error) = std::io::stdout().flush() {
        eprintln!("could not display GCP login preview ({})", error.kind());
        return 5;
    }

    let Ok((current_config, _)) = load_user_config() else {
        eprintln!("refusing GCP login: authentication context could not be re-resolved");
        return 6;
    };
    let Ok(current_definition) = current_config.resolve_context_definition(definition.name())
    else {
        eprintln!("refusing GCP login: authentication context could not be re-resolved");
        return 6;
    };
    if let Err(failure) = GcpLoginPlan::ensure_unchanged(definition, &current_definition) {
        eprintln!("{failure}");
        return failure.exit_code();
    }

    let runner = match SecureProcessRunner::for_authmux() {
        Ok(runner) => runner,
        Err(failure) => {
            eprintln!("{failure}");
            return 2;
        }
    };
    match runner.run(plan.command(), plan.selection()) {
        Ok(outcome) => match (outcome.exit_code(), outcome.signal()) {
            (Some(0), None) => {
                println!(
                    "result: native GCP login command exited successfully; live session usability remains unverified"
                );
                0
            }
            (Some(code), None) => {
                eprintln!("native GCP login command exited with status {code}");
                code
            }
            (None, Some(signal)) => terminate_with_signal(signal),
            _ => {
                eprintln!("native GCP login command ended without an exit code or signal");
                5
            }
        },
        Err(failure) => {
            eprintln!("{failure}");
            exit_code(&failure)
        }
    }
}

fn login_ssh(definition: &ContextDefinition) -> i32 {
    let Some(profile) = definition.ssh() else {
        eprintln!("SSH Provider Profile is not configured");
        return 2;
    };
    let command = match CommandSpec::new("ssh", [profile.host_alias()]) {
        Ok(command) => command,
        Err(failure) => {
            eprintln!("{failure}");
            return 2;
        }
    };

    println!("login: {}", definition.name());
    println!("provider: ssh");
    println!("host alias: {}", profile.host_alias());
    println!(
        "expected remote principal: {}",
        profile.expected_remote_principal()
    );
    println!("native command: ssh {}", profile.host_alias());
    if let Err(error) = std::io::stdout().flush() {
        eprintln!("could not display SSH login preview ({})", error.kind());
        return 5;
    }

    let runner = match SecureProcessRunner::for_authmux() {
        Ok(runner) => runner,
        Err(failure) => {
            eprintln!("{failure}");
            return 2;
        }
    };
    match runner.run(&command, &ExecutionSelection::none()) {
        Ok(outcome) => match (outcome.exit_code(), outcome.signal()) {
            (Some(0), None) => {
                println!(
                    "result: native login command exited successfully; remote session usability remains unverified"
                );
                match observe_ssh_transport(definition) {
                    Ok(observation) => println!(
                        "post-login transport reuse: {}",
                        ssh_transport_reuse_label(observation.transport_reuse())
                    ),
                    Err(_) => println!("post-login transport reuse: unknown"),
                }
                0
            }
            (Some(code), None) => {
                eprintln!("native SSH login command exited with status {code}");
                code
            }
            (None, Some(signal)) => terminate_with_signal(signal),
            _ => {
                eprintln!("native SSH login command ended without an exit code or signal");
                5
            }
        },
        Err(failure) => {
            eprintln!("{failure}");
            exit_code(&failure)
        }
    }
}

fn execute(selection: ContextSelection, command: &CommandSpec) -> i32 {
    let resolved = match resolve_selection(selection.clone()) {
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
    let definition = match config.resolve_context_definition(&resolved.context_name) {
        Ok(definition) => definition,
        Err(failure) => {
            eprintln!("{failure}");
            return 2;
        }
    };

    match (definition.aws(), definition.gcp(), definition.ssh()) {
        (Some(_), None, _) => execute_aws(selection, command),
        (None, Some(profile), None) => execute_gcp(selection, &definition, profile, command),
        (_, Some(_), _) => {
            let failure = GcpExecutionFailure::UnsupportedProviderComposition;
            eprintln!("{failure}");
            failure.exit_code()
        }
        _ => {
            eprintln!(
                "requested authentication context does not define AWS required by this command"
            );
            2
        }
    }
}

fn execute_aws(selection: ContextSelection, command: &CommandSpec) -> i32 {
    let current_resolver = CliExecutionContextResolver {
        selection: selection.clone(),
    };
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

    let probe_runner = match SecureProcessRunner::for_authmux() {
        Ok(runner) => runner,
        Err(failure) => {
            eprintln!("{failure}");
            return 2;
        }
    };
    let child_runner = match SecureProcessRunner::for_authmux() {
        Ok(runner) => runner,
        Err(failure) => {
            eprintln!("{failure}");
            return 2;
        }
    };
    let engine = ContextEngine::new(AwsAdapter::new(probe_runner), child_runner);

    match engine.execute(&context, command, &current_resolver) {
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

fn execute_gcp(
    selection: ContextSelection,
    definition: &ContextDefinition,
    profile: &authmux::GcpProviderDefinition,
    command: &CommandSpec,
) -> i32 {
    let Some(home) = env::var_os("HOME") else {
        eprintln!(
            "refusing child execution: user home is unavailable for protected GCP observation"
        );
        return 4;
    };
    let Ok(observations) = GcpLocalStatus::new(PathBuf::from(home)).observe(profile) else {
        eprintln!("refusing child execution: protected GCP selection could not be observed safely");
        return 5;
    };
    let execution_selection = match GcpExecutionGuard::authorize(profile, &observations, command) {
        Ok(selection) => selection,
        Err(failure) => {
            eprintln!("{failure}");
            return failure.exit_code();
        }
    };

    let Ok(current_selection) = resolve_selection(selection) else {
        return refuse_changed_context();
    };
    let Ok((current_config, _)) = load_user_config() else {
        return refuse_changed_context();
    };
    let Ok(current_definition) =
        current_config.resolve_context_definition(&current_selection.context_name)
    else {
        return refuse_changed_context();
    };
    if let Err(failure) = GcpExecutionGuard::ensure_unchanged(definition, &current_definition) {
        eprintln!("{failure}");
        return failure.exit_code();
    }

    let runner = match SecureProcessRunner::for_authmux() {
        Ok(runner) => runner,
        Err(failure) => {
            eprintln!("{failure}");
            return 2;
        }
    };
    match runner.run(command, &execution_selection) {
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

fn refuse_changed_context() -> i32 {
    let failure = ExecutionFailure::ContextChanged;
    eprintln!("{failure}");
    exit_code(&failure)
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

fn show_status(
    selection: ContextSelection,
    provider: Option<ProviderSelection>,
    format: ReportFormat,
    require_active_transport: bool,
) -> i32 {
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
    let definition = match config.resolve_context_definition(&selection.context_name) {
        Ok(definition) => definition,
        Err(failure) => {
            eprintln!("{failure}");
            return 2;
        }
    };
    let provider = match resolve_status_provider(&definition, provider) {
        Ok(provider) => provider,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };
    if require_active_transport && provider != ProviderSelection::Ssh {
        eprintln!("--require-active-transport requires an SSH Provider Profile");
        return 2;
    }
    let report = match provider {
        ProviderSelection::Aws => aws_status_report(&definition).map(|report| (report, None)),
        ProviderSelection::Ssh => ssh_status_report(&definition)
            .map(|(report, transport_reuse)| (report, Some(transport_reuse))),
        ProviderSelection::Gcp => gcp_status_report(&definition).map(|report| (report, None)),
    };
    let (report, transport_reuse) = match report {
        Ok(report) => report,
        Err(exit_code) => return exit_code,
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
    if require_active_transport {
        return require_active_ssh_transport(&selection.context_name, transport_reuse);
    }
    0
}

fn aws_status_report(definition: &ContextDefinition) -> Result<StatusReport, i32> {
    let Some(context) = definition.aws() else {
        eprintln!("AWS Provider Profile is not configured");
        return Err(2);
    };
    let runner = SecureProcessRunner::for_authmux().map_err(|failure| {
        eprintln!("{failure}");
        2
    })?;
    let engine = StatusEngine::new(AwsLocalMetadataAdapter::new(runner));
    let observation = engine.observe(context).map_err(|failure| {
        eprintln!("provider status failed: {failure}");
        5
    })?;
    StatusReport::local_aws(context, &observation).map_err(|failure| {
        eprintln!("could not render status: {failure}");
        5
    })
}

fn ssh_status_report(
    definition: &ContextDefinition,
) -> Result<(StatusReport, SshTransportReuse), i32> {
    let Some(profile) = definition.ssh() else {
        eprintln!("SSH Provider Profile is not configured");
        return Err(2);
    };
    let observation = observe_ssh_transport(definition)?;
    let transport_reuse = observation.transport_reuse();
    let report =
        StatusReport::local_ssh(definition.name(), profile, &observation).map_err(|failure| {
            eprintln!("could not render status: {failure}");
            5
        })?;
    Ok((report, transport_reuse))
}

fn observe_ssh_transport(definition: &ContextDefinition) -> Result<SshTransportObservation, i32> {
    let Some(profile) = definition.ssh() else {
        eprintln!("SSH Provider Profile is not configured");
        return Err(2);
    };
    let Some(home) = env::var_os("HOME") else {
        eprintln!("SSH transport status requires HOME");
        return Err(2);
    };
    let runner = SecureProcessRunner::for_authmux().map_err(|failure| {
        eprintln!("{failure}");
        2
    })?;
    let status = SshTransportStatus::new(runner, PathBuf::from(home).join(".ssh"));
    status.observe(profile).map_err(|failure| {
        eprintln!("provider status failed: {failure}");
        5
    })
}

fn ssh_transport_reuse_label(transport_reuse: SshTransportReuse) -> &'static str {
    match transport_reuse {
        SshTransportReuse::Active => "active",
        SshTransportReuse::Inactive => "inactive",
        SshTransportReuse::Unknown => "unknown",
    }
}

fn require_active_ssh_transport(
    context_name: &str,
    transport_reuse: Option<SshTransportReuse>,
) -> i32 {
    match transport_reuse {
        Some(SshTransportReuse::Active) => 0,
        Some(SshTransportReuse::Inactive) => {
            eprintln!(
                "SSH transport preflight failed: reusable transport is inactive; run `authmux login {context_name} --provider ssh`"
            );
            1
        }
        Some(SshTransportReuse::Unknown) | None => {
            eprintln!(
                "SSH transport preflight failed: reusable transport could not be verified; run `authmux login {context_name} --provider ssh`"
            );
            5
        }
    }
}

fn gcp_status_report(definition: &ContextDefinition) -> Result<StatusReport, i32> {
    let Some(profile) = definition.gcp() else {
        eprintln!("GCP Provider Profile is not configured");
        return Err(2);
    };
    let Some(home) = env::var_os("HOME") else {
        eprintln!("GCP status requires HOME");
        return Err(2);
    };
    let observations = GcpLocalStatus::new(PathBuf::from(home))
        .observe(profile)
        .map_err(|failure| {
            eprintln!("provider status failed: {failure}");
            5
        })?;
    StatusReport::local_gcp(definition.name(), profile, &observations).map_err(|failure| {
        eprintln!("could not render status: {failure}");
        5
    })
}

fn show_doctor(
    selection: ContextSelection,
    provider: Option<ProviderSelection>,
    format: ReportFormat,
) -> i32 {
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
    let definition = match config.resolve_context_definition(&selection.context_name) {
        Ok(definition) => definition,
        Err(failure) => {
            eprintln!("{failure}");
            return 2;
        }
    };
    let provider = match resolve_doctor_provider(&definition, provider) {
        Ok(provider) => provider,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };
    let result = match diagnose_provider(&definition, provider) {
        Ok(result) => result,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };
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

fn resolve_doctor_provider(
    definition: &ContextDefinition,
    requested: Option<ProviderSelection>,
) -> Result<ProviderSelection, String> {
    if let Some(provider) = requested {
        let configured = match provider {
            ProviderSelection::Aws => definition.aws().is_some(),
            ProviderSelection::Ssh => definition.ssh().is_some(),
            ProviderSelection::Gcp => definition.gcp().is_some(),
        };
        return configured.then_some(provider).ok_or_else(|| {
            "requested authentication context does not define the selected provider".to_owned()
        });
    }

    let configured = [
        definition.aws().is_some().then_some(ProviderSelection::Aws),
        definition.ssh().is_some().then_some(ProviderSelection::Ssh),
        definition.gcp().is_some().then_some(ProviderSelection::Gcp),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    match configured.as_slice() {
        [provider] => Ok(*provider),
        [] => Err("authentication context does not define a provider".to_owned()),
        _ => Err(
            "doctor requires --provider when the authentication context defines multiple providers"
                .to_owned(),
        ),
    }
}

fn resolve_status_provider(
    definition: &ContextDefinition,
    requested: Option<ProviderSelection>,
) -> Result<ProviderSelection, String> {
    if let Some(provider) = requested {
        let configured = match provider {
            ProviderSelection::Aws => definition.aws().is_some(),
            ProviderSelection::Ssh => definition.ssh().is_some(),
            ProviderSelection::Gcp => definition.gcp().is_some(),
        };
        return configured.then_some(provider).ok_or_else(|| {
            "requested authentication context does not define the selected provider".to_owned()
        });
    }

    let configured = [
        definition.aws().is_some().then_some(ProviderSelection::Aws),
        definition.ssh().is_some().then_some(ProviderSelection::Ssh),
        definition.gcp().is_some().then_some(ProviderSelection::Gcp),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    match configured.as_slice() {
        [provider] => Ok(*provider),
        [] => Err("authentication context does not define a provider".to_owned()),
        _ => Err(
            "status requires --provider when the authentication context defines multiple providers"
                .to_owned(),
        ),
    }
}

fn resolve_login_provider(
    definition: &ContextDefinition,
    requested: Option<ProviderSelection>,
) -> Result<ProviderSelection, String> {
    if let Some(provider) = requested {
        let configured = match provider {
            ProviderSelection::Aws => definition.aws().is_some(),
            ProviderSelection::Ssh => definition.ssh().is_some(),
            ProviderSelection::Gcp => definition.gcp().is_some(),
        };
        return configured.then_some(provider).ok_or_else(|| {
            "requested authentication context does not define the selected provider".to_owned()
        });
    }

    let configured = [
        definition.aws().is_some().then_some(ProviderSelection::Aws),
        definition.ssh().is_some().then_some(ProviderSelection::Ssh),
        definition.gcp().is_some().then_some(ProviderSelection::Gcp),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    match configured.as_slice() {
        [provider] => Ok(*provider),
        [] => Err("authentication context does not define a provider".to_owned()),
        _ => Err(
            "login requires --provider when the authentication context defines multiple providers"
                .to_owned(),
        ),
    }
}

fn diagnose_provider(
    definition: &ContextDefinition,
    provider: ProviderSelection,
) -> Result<authmux::DoctorResult, String> {
    match provider {
        ProviderSelection::Aws => {
            let version_runner =
                SecureProcessRunner::for_authmux().map_err(|failure| failure.to_string())?;
            let status_runner =
                SecureProcessRunner::for_authmux().map_err(|failure| failure.to_string())?;
            let context = definition
                .aws()
                .ok_or_else(|| "AWS Provider Profile is not configured".to_owned())?;
            Ok(AwsDoctor::new(version_runner, status_runner).diagnose(context))
        }
        ProviderSelection::Ssh => {
            let runner =
                SecureProcessRunner::for_authmux().map_err(|failure| failure.to_string())?;
            let profile = definition
                .ssh()
                .ok_or_else(|| "SSH Provider Profile is not configured".to_owned())?;
            Ok(SshDoctor::new(runner).diagnose(definition.name(), profile))
        }
        ProviderSelection::Gcp => {
            let profile = definition
                .gcp()
                .ok_or_else(|| "GCP Provider Profile is not configured".to_owned())?;
            let home = env::var_os("HOME").ok_or_else(|| "GCP doctor requires HOME".to_owned())?;
            Ok(GcpDoctor::new(PathBuf::from(home), env::var_os("PATH"))
                .diagnose(definition.name(), profile))
        }
    }
}

fn print_context(
    selection: &ResolvedSelection,
    definition: &ContextDefinition,
    definition_source: &std::path::Path,
) {
    println!("context: {}", definition.name());
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
    if let Some(context) = definition.aws() {
        println!("aws profile: {}", context.provider_profile());
        println!("expected AWS account: {}", context.expected_account());
    }
    if let Some(ssh) = definition.ssh() {
        println!("ssh host alias: {}", ssh.host_alias());
        println!(
            "expected SSH remote principal: {}",
            ssh.expected_remote_principal()
        );
    }
    if let Some(gcp) = definition.gcp() {
        if let Some(gcloud) = gcp.gcloud() {
            println!("gcloud configuration: {}", gcloud.configuration());
            println!("expected gcloud identity: {}", gcloud.expected_principal());
            if let Some(source) = gcloud.expected_source_account() {
                println!("expected gcloud source identity: {source}");
            }
            if let Some(project) = gcloud.expected_project() {
                println!("expected gcloud project: {project}");
            }
        }
        if let Some(adc) = gcp.adc() {
            println!("ADC mode: credential_file");
            println!("expected ADC identity: {}", adc.expected_principal());
        }
    }
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
        provider: Option<ProviderSelection>,
        format: ReportFormat,
        require_active_transport: bool,
    },
    Login {
        selection: ContextSelection,
        provider: Option<ProviderSelection>,
    },
    Doctor {
        selection: ContextSelection,
        provider: Option<ProviderSelection>,
        format: ReportFormat,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderSelection {
    Aws,
    Ssh,
    Gcp,
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

struct CliExecutionContextResolver {
    selection: ContextSelection,
}

impl ExecutionContextResolver for CliExecutionContextResolver {
    fn resolve_current(&self) -> Result<authmux::AuthenticationContext, ExecutionFailure> {
        let selection = resolve_selection(self.selection.clone())
            .map_err(|_| ExecutionFailure::ContextResolution)?;
        let (config, _) = load_user_config().map_err(|_| ExecutionFailure::ContextResolution)?;
        config
            .resolve_context(&selection.context_name)
            .map_err(|_| ExecutionFailure::ContextResolution)
    }
}

fn parse_command(arguments: Vec<OsString>) -> Result<CliCommand, String> {
    match arguments.first().and_then(|argument| argument.to_str()) {
        Some("exec") => parse_exec(arguments)
            .map(|(selection, command)| CliCommand::Exec { selection, command }),
        Some("context") => parse_context_command(&arguments),
        Some("status") => parse_status(&arguments).map(
            |(selection, provider, format, require_active_transport)| CliCommand::Status {
                selection,
                provider,
                format,
                require_active_transport,
            },
        ),
        Some("login") => parse_login(&arguments).map(|(selection, provider)| CliCommand::Login {
            selection,
            provider,
        }),
        Some("doctor") => {
            parse_doctor(&arguments).map(|(selection, provider, format)| CliCommand::Doctor {
                selection,
                provider,
                format,
            })
        }
        _ => Err("usage: authmux <exec|context|doctor|login|status> ...".to_owned()),
    }
}

fn parse_login(
    arguments: &[OsString],
) -> Result<(ContextSelection, Option<ProviderSelection>), String> {
    const USAGE: &str = "usage: authmux login <context> [--provider <aws|gcp|ssh>]";
    let context_name = arguments
        .get(1)
        .and_then(|argument| argument.to_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| USAGE.to_owned())?
        .to_owned();

    let provider = match arguments.len() {
        2 => None,
        4 if arguments.get(2).and_then(|argument| argument.to_str()) == Some("--provider") => {
            match arguments.get(3).and_then(|argument| argument.to_str()) {
                Some("aws") => Some(ProviderSelection::Aws),
                Some("gcp") => Some(ProviderSelection::Gcp),
                Some("ssh") => Some(ProviderSelection::Ssh),
                _ => return Err(USAGE.to_owned()),
            }
        }
        _ => return Err(USAGE.to_owned()),
    };

    Ok((ContextSelection::Explicit(context_name), provider))
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

fn parse_status(
    arguments: &[OsString],
) -> Result<
    (
        ContextSelection,
        Option<ProviderSelection>,
        ReportFormat,
        bool,
    ),
    String,
> {
    const USAGE: &str = "usage: authmux status [--context <context>] [--provider <aws|gcp|ssh>] [--json] [--require-active-transport]";
    let mut selection = None;
    let mut provider = None;
    let mut format = ReportFormat::Human;
    let mut require_active_transport = false;
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
            Some("--provider") if provider.is_none() => {
                provider = match arguments
                    .get(index + 1)
                    .and_then(|argument| argument.to_str())
                {
                    Some("aws") => Some(ProviderSelection::Aws),
                    Some("gcp") => Some(ProviderSelection::Gcp),
                    Some("ssh") => Some(ProviderSelection::Ssh),
                    _ => return Err(USAGE.to_owned()),
                };
                index += 2;
            }
            Some("--require-active-transport") if !require_active_transport => {
                require_active_transport = true;
                index += 1;
            }
            _ => return Err(USAGE.to_owned()),
        }
    }

    Ok((
        selection.unwrap_or(ContextSelection::ProjectBound),
        provider,
        format,
        require_active_transport,
    ))
}

fn parse_doctor(
    arguments: &[OsString],
) -> Result<(ContextSelection, Option<ProviderSelection>, ReportFormat), String> {
    const USAGE: &str =
        "usage: authmux doctor [--context <context>] [--provider <aws|gcp|ssh>] [--json]";
    let mut selection = None;
    let mut provider = None;
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
            Some("--provider") if provider.is_none() => {
                provider = match arguments
                    .get(index + 1)
                    .and_then(|argument| argument.to_str())
                {
                    Some("aws") => Some(ProviderSelection::Aws),
                    Some("gcp") => Some(ProviderSelection::Gcp),
                    Some("ssh") => Some(ProviderSelection::Ssh),
                    _ => return Err(USAGE.to_owned()),
                };
                index += 2;
            }
            _ => return Err(USAGE.to_owned()),
        }
    }

    Ok((
        selection.unwrap_or(ContextSelection::ProjectBound),
        provider,
        format,
    ))
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
        ExecutionFailure::ContextResolution => 2,
        ExecutionFailure::ContextChanged => 6,
        ExecutionFailure::IdentityMismatch { .. } => 3,
        ExecutionFailure::SessionUnusable { .. }
        | ExecutionFailure::SessionIndeterminate { .. } => 4,
        ExecutionFailure::Provider(_) => 5,
        ExecutionFailure::Process(_) => 126,
    }
}

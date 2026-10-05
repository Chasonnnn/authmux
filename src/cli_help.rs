use std::ffi::OsString;

pub const TOP_USAGE: &str =
    "usage: authmux <exec|context|doctor|login|status|aws|gh|gcloud|empireai> ...";
pub const EXEC_USAGE: &str = "usage: authmux exec [--context <context>] -- <program> [args...]";
pub const LOGIN_USAGE: &str =
    "usage: authmux login <context> [--provider <aws|gcp|github|ssh>] [--print-command]";
pub const SHORTCUT_USAGE: &str =
    "usage: authmux <aws|gh|gcloud|empireai> [--context <context>] [--print-command]";
pub const STATUS_USAGE: &str = "usage: authmux status [--all | --context <context>] [--provider <aws|gcp|github|ssh>] [--json] [--require-active-transport]";
pub const DOCTOR_USAGE: &str =
    "usage: authmux doctor [--context <context>] [--provider <aws|gcp|github|ssh>] [--json]";
pub const CONTEXT_USAGE: &str = "usage: authmux context <list|show> ...";
pub const CONTEXT_LIST_USAGE: &str = "usage: authmux context list [--json]";
pub const CONTEXT_SHOW_USAGE: &str = "usage: authmux context show [--context <context>]";

pub fn render(arguments: &[OsString]) -> Option<String> {
    // Arguments after the exec delimiter belong to the child, including help flags.
    if !arguments
        .iter()
        .take_while(|argument| *argument != "--")
        .any(|argument| argument == "--help" || argument == "-h")
    {
        return None;
    }
    let (usage, details) = match arguments.first()?.to_str()? {
        "--help" | "-h" if arguments.len() == 1 => (
            TOP_USAGE,
            "exec       Run a guarded command with the selected identity.\n\
             context    List configured contexts or show project selection.\n\
             status     Observe provider identity and session evidence.\n\
             doctor     Diagnose local configuration and CLI availability.\n\
             login      Delegate explicit login to a native provider.\n\
             aws, gh, gcloud, empireai  Log in using a repo provider mapping.\n\n\
             --version, -V  Print the installed package version.",
        ),
        "exec" => (
            EXEC_USAGE,
            "--context NAME  Select an explicit context; otherwise use the project binding.\n\
             --              Pass the remaining arguments unchanged to the child.\n\
             Provider login mappings do not automatically select the execution context.",
        ),
        "login" => (
            LOGIN_USAGE,
            "--provider NAME  Select one provider when the context defines several.\n\
             --print-command  Preview login without starting the native command.\n\
             Run interactive login in a separate terminal app, outside captured agent sessions.",
        ),
        "aws" | "gh" | "gcloud" | "empireai" => (
            SHORTCUT_USAGE,
            "aws = AWS; gh = GitHub; gcloud = GCP; empireai = SSH.\n\
             --context NAME   Override the repo provider mapping and default context.\n\
             --print-command  Preview login without starting the native command.\n\
             Shortcuts log in only. Use exec for guarded provider commands.",
        ),
        "status" => (
            STATUS_USAGE,
            "--all                       Observe every configured context without a project binding.\n\
             --context NAME              Override the project context.\n\
             --provider NAME             Observe one provider.\n\
             --json                      Emit the versioned status report.\n\
             --require-active-transport  Require active SSH transport reuse.\n\
             --all cannot be combined with context, provider, or transport selection.\n\
             Local metadata does not prove live provider access.",
        ),
        "doctor" => (
            DOCTOR_USAGE,
            "--context NAME   Override the project context.\n\
             --provider NAME  Diagnose one provider.\n\
             --json           Emit the versioned diagnostic report.\n\
             Checks are local and read-only. Warnings exit 0; failed checks exit 1.",
        ),
        "context" => match arguments.get(1)?.to_str()? {
            "--help" | "-h" => (
                CONTEXT_USAGE,
                "list  List configured contexts without provider contact.\n\
                 show  Show the project binding or an explicit context.",
            ),
            "list" => (
                CONTEXT_LIST_USAGE,
                "--json  Emit the versioned context list.",
            ),
            "show" => (
                CONTEXT_SHOW_USAGE,
                "--context NAME  Inspect an explicit context without a project binding.",
            ),
            _ => return None,
        },
        _ => return None,
    };
    Some(format!(
        "{usage}\n\n{details}\n\n--help, -h  Print help without loading configuration or contacting a provider."
    ))
}

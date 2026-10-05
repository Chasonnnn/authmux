---
name: authmux
description: Route authenticated AWS, Google Cloud, GitHub CLI, and SSH work through a repository-bound authmux context with one guarded execution path and an external-terminal handoff for interactive login.
---

# Authmux

Use authmux only as the authentication-context boundary. Native providers and
the operating system retain credential custody.

## Normal path

1. Read the target repository's agent and deployment instructions.
2. In an unfamiliar repository, or after its working directory, Project
   Binding, or user configuration changes, run `authmux context show` once.
   Otherwise do not repeat it.
3. For `gh`, select the GitHub context under **GitHub CLI** below. For other
   providers, run the requested leaf operation through `authmux exec -- ...`.
   If the repo declares a separate login context for that provider, select it
   explicitly with `--context CONTEXT` for the operation; mappings do not
   automatically route `exec`, `status`, or `doctor`.
   Guarded execution resolves the binding, validates the provider evidence it
   requires, filters ambient credentials, and fails closed.
   Preserve the exact argv until the operation finishes or its single
   continuity retry is exhausted.
4. Do not run `status` or `doctor` as a routine preflight. Use `status` for an
   explicit overview or identity investigation and `doctor` for configuration
   or CLI diagnosis.

Examples:

```console
authmux exec -- aws s3 ls
authmux exec -- terraform plan
authmux exec -- gcloud projects describe PROJECT_ID
authmux exec --context GITHUB_CONTEXT -- gh pr list
```

Use `--context CONTEXT` when the repository mapping, repository instructions,
or user identifies that context, or for GitHub selection below. Never guess a
context from a shortcut name.

## Repo login shortcuts

For explicit login requests, use the configured repo's shortcut:

| Command | Provider | Repo mapping |
|---|---|---|
| `authmux aws` | AWS | `project.providers.aws` |
| `authmux gh` | GitHub | `project.providers.github` |
| `authmux gcloud` | GCP | `project.providers.gcp` |
| `authmux empireai` | SSH | `project.providers.ssh` |

Each accepts `--context CONTEXT` and `--print-command`. Explicit context wins;
otherwise the matching repo mapping wins, with `project.context` used only
when that provider has no mapping. An invalid mapping or missing provider is
an error, not permission to try another context. `empireai` uses the configured
SSH host alias; it does not select a hardcoded cluster.

Repo configuration keeps the default context and references existing user
contexts, for example:

```toml
version = 1
[project]
context = "research"
[project.providers]
aws = "research"
github = "github"
ssh = "empire"
```

`authmux context show` lists these login mappings. Install a binary that
supports shortcuts before adding the table; older versions reject it. Do not
rewrite repo bindings merely to perform a login.

In captured sessions, run only the shortcut with `--print-command`.
Have the user open a separate terminal app, such as Terminal, iTerm, or Ghostty.
They rerun the command without the flag from the same repository, outside
Codex or Claude. Do not use a chat shell command.
An explicit `--context` may select the resolved context instead.
These shortcuts log in only; they never forward provider arguments.
Guarded operations still use `exec`. Keep the exact event-provided login argv
for recovery below.

## GitHub CLI

GitHub PRs, reviews, checks, Actions, and repository API calls require GitHub
authentication. An AWS or GCP Project Binding does not make cloud login a
prerequisite for these operations.

- If `project.providers.github` is declared, use that GitHub-only context with
  `--context` before the first operation. A missing or incompatible mapped
  context stops the operation; do not fall back to discovery.
- Otherwise use the default bound context when it is GitHub-only.
- If neither applies, inspect `authmux context list --json` once. When exactly one
  GitHub-only context matches the target host and repository instructions do
  not require another GitHub identity, use it explicitly:
  `authmux exec --context GITHUB_CONTEXT -- gh ...`. Keep the repository
  working directory and requested `gh` arguments.
- If the required GitHub identity is unclear or no matching context exists,
  ask for the GitHub context. Do not change the cloud binding or substitute
  ambient authentication.
- Select the GitHub context before the first `gh` run, never after a failure.
- Never request AWS, GCP, or SSH login to unblock a `gh` operation. An older
  authmux may emit an AWS Reauthentication event when `gh` ran under an AWS
  context; reject that mismatched event and run the same `gh` argv once under
  the GitHub context selected above. This is the only cross-context retry the
  command boundaries below allow.

If guarded execution reports unverified GitHub system credential storage,
check whether the execution environment restricts credential-store access.
When it does, request scoped access for the exact guarded command and retry
once. Stop if that retry fails. Do not rerun unchanged restricted commands,
request login from this diagnostic alone, or weaken secure-storage checks.
A confirmed plaintext-storage diagnostic requires native secure-storage repair
in a separate terminal app before another guarded attempt.

Mixed-provider execution remains unsupported. Selecting an existing GitHub-only
context keeps its Expected Identity and credential-store guard in force.

## Interactive reauthentication

Exit code `10` means stderr must contain one `exec-event-v1` JSON object. Accept
it only when `event` is `reauthentication_required`, its context and provider
match the attempted operation, and `retry` is `original_command_once`. A
missing, malformed, or mismatched event fails closed.

Run the event's `login_argv` exactly once inside the captured agent session. It
must end in `--print-command`, so it plans one provider without starting native
login:

```console
authmux login CONTEXT --provider PROVIDER --print-command
```

Then report that the user should rerun the same `authmux login` without
`--print-command` in a separate terminal app (Terminal, iTerm, or Ghostty),
outside Codex or Claude. Chat shell commands retain native output even when
the user starts them. Stop that provider operation until the user confirms
completion.
Keeping authmux in the external path preserves provider selectors omitted from
the sanitized native-command preview. Never ask the user to paste provider
output, a browser URL, device or authorization code, password, token, or MFA
value. After confirmation, retry the preserved original argv once without a
status round trip. Report the original operation's substantive result.
Native login success leaves the operation pending. Recovery is complete only
when its guarded retry succeeds. If it returns exit code `10` again, report
the repeated Reauthentication requirement and stop. Never start a second login
or switch identity.

GCP child failures do not produce this event because authmux cannot safely
classify arbitrary child output. Do not infer Reauthentication from a generic
nonzero child exit or retry it automatically.

If AWS identity observation reports that it could not reach the provider, do
not start login. Request network access for the preserved guarded command and
retry it once. Stop if the network-enabled retry fails; do not bypass authmux.
An unclassified exit-5 provider failure does not establish expiry or missing
credentials. Do not recommend login from that failure alone.

## Native Git

Run native `git fetch`, `git pull`, and `git push` directly through the
repository's configured Git/SSH transport. Never require an authmux SSH
Provider Profile or SSH status check for a Git remote, including
`git@github.com` remotes. This is not an authmux bypass: authmux has no raw-Git
selector contract and does not manage Git authentication.

## Command and approval boundaries

- Run a literal leaf command, not `authmux exec -- sh`, `bash`, `zsh`, `env`,
  or another general command launcher.
- Scope durable approvals to the required guarded command family, such as
  `authmux exec -- aws`; never request a blanket `authmux` prefix.
- Never bypass a mismatch, context drift, unsupported provider composition, or
  inactive required SSH transport with a bare provider command or ambient
  selector.
- Preserve child exit codes and do not retry through another context or
  identity, except the single `gh` retry under **GitHub CLI**.

## Provider boundaries

- AWS, Google Cloud, and GitHub use guarded `authmux exec` paths. GitHub accepts
  `gh`, not raw Git authentication.
- SSH has no generic `exec` path. Before automated SSH work, require
  `authmux status --context CONTEXT --provider ssh --require-active-transport`,
  selecting the repo's `project.providers.ssh` context when declared; after it
  passes, use that context's native SSH host alias. If it fails for
  inactivity, use the external-terminal login handoff above.
- For unattended deployment or log monitoring that may exceed a human Session,
  use the repository's approved OIDC or workload-identity workflow. Do not keep
  a user Session alive with a timer, create static cloud keys, or launch the
  whole coding agent inside authmux.

For authentication reporting, include only the resolved Authentication Context
and provider, the required identity or transport evidence, the guarded command
category and outcome, and the sanitized Reauthentication command when blocked.

Also report the requested operation's substantive result; the authentication
summary does not replace it.

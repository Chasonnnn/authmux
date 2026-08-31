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
3. Run the requested leaf operation directly through `authmux exec -- ...`.
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
authmux exec -- gh pr list
```

Use `--context CONTEXT` only outside a bound repository and only when repository
instructions or the user already identify that context.

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
`--print-command` in a separate terminal, then stop that provider operation.
Keeping authmux in the external path preserves provider selectors omitted from
the sanitized native-command preview. Never ask the user to paste provider
output, a browser URL, device or authorization code, password, token, or MFA
value. After confirmation, retry the preserved original argv once without a
status round trip. If it returns exit code `10` again, stop and report the
repeated Reauthentication requirement; never start a second login or switch
identity.

GCP child failures do not produce this event because authmux cannot safely
classify arbitrary child output. Do not infer Reauthentication from a generic
nonzero child exit or retry it automatically.

If AWS identity observation reports that it could not reach the provider, do
not start login. Request network access for the preserved guarded command and
retry it once. Stop if the network-enabled retry fails; do not bypass authmux.

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
  identity.

## Provider boundaries

- AWS, Google Cloud, and GitHub use guarded `authmux exec` paths. GitHub accepts
  `gh`, not raw Git authentication.
- SSH has no generic `exec` path. Before automated SSH work, require
  `authmux status --context CONTEXT --provider ssh --require-active-transport`;
  after it passes, use the repository's native SSH host alias. If it fails for
  inactivity, use the external-terminal login handoff above.
- For unattended deployment or log monitoring that may exceed a human Session,
  use the repository's approved OIDC or workload-identity workflow. Do not keep
  a user Session alive with a timer, create static cloud keys, or launch the
  whole coding agent inside authmux.

Report only the resolved Authentication Context and provider, the required
identity or transport evidence, the guarded command category and outcome, and
the sanitized Reauthentication command when blocked.

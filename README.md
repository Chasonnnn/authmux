# authmux

`authmux` is an early local-first CLI for verifying and selecting authentication
contexts across developer tools without becoming a credential vault itself.

The repository is private during design and early validation. The code and
documentation are licensed under the MIT License so the project can be opened
when its security model and provider behavior are ready for public scrutiny.

## Current tracer

```console
authmux exec --context crm -- aws s3 ls
```

Inside a Git repository whose root contains a restricted `.authmux.toml`
binding, omit the explicit selector:

```console
authmux exec -- aws s3 ls
```

Inspect the resolved intent and provenance without invoking AWS:

```console
authmux context list
authmux context list --json
authmux context show
authmux context show --context crm
```

Use `context show` when beginning work in an unfamiliar repository or after the
working directory, binding, or configuration changes. It is not a required
preflight before every command: guarded `exec` resolves the binding, validates
the selected provider, and fails closed itself.

Inspect documented local AWS profile metadata without contacting AWS or
refreshing a Session:

```console
authmux status
authmux status --context crm
authmux status --context crm --json
```

Inspect every configured provider from any directory:

```console
authmux status --all
authmux status --all --json
```

The aggregate command does not require a repository Project Binding. It keeps
successful observations when another provider fails and exits nonzero so an
agent can fail closed. Its JSON output follows the checked-in
[`status-all-v1` schema](docs/schemas/status-all-v1.schema.json).

This status can detect whether an IAM Identity Center profile's configured
account or an AWS login profile's `login_session` account matches the Expected
Identity. It retains only the account segment of supported AWS ARNs. It always
reports Session Usability as `indeterminate`; use guarded `exec` when
provider-validated identity evidence is required.

Explicit AWS Reauthentication delegates to the native profile mode:

```console
authmux login crm --provider aws
authmux login crm --provider aws --print-command
```

Console-login profiles use `aws login`; IAM Identity Center profiles use
`aws sso login`. For a role profile, authmux validates the selected role's
target account and reauthenticates its declared source profile. The preview
shows both profile selectors before the terminal-attached native command runs.
Native success does not by itself claim live Session Usability.

`--print-command` performs the same bounded planning and sanitized preview but
does not start the native login. Use it from Codex, Claude, CI, or another
captured agent session, then rerun the same `authmux login` without
`--print-command` in a separate user-controlled terminal. This preserves
process-scoped provider selectors while keeping browser URLs, device codes,
MFA prompts, and native login output out of the agent transcript. After the
user confirms completion, retry the original guarded command; do not add a
routine `status` round trip.

GitHub uses a user-owned native configuration directory and the system
credential store:

```toml
[contexts.github.providers.github]
config_dir = "/home/researcher/.config/gh/research"
hostname = "github.com"
expected_login = "fictional-researcher"
```

```console
authmux status --context github --provider github
authmux doctor --context github --provider github
authmux login github --provider github
authmux exec --context github -- gh pr list
```

Status contacts GitHub through `gh auth status` without requesting or printing
a token. Guarded execution validates the active login, then applies
`GH_CONFIG_DIR` and `GH_HOST` only to the child. Ambient GitHub token variables
are removed. Authmux rejects GitHub CLI plaintext-token fallback; configure a
supported system credential store instead. GitHub execution accepts only `gh`;
raw `git` authentication is not selected by `GH_CONFIG_DIR` and fails closed.

For GitHub work inside a repository bound to AWS or GCP, select a configured
GitHub-only context explicitly, as above. `authmux context list --json` shows
the declared providers and Expected Identities without contacting them. A `gh`
command with no GitHub Provider Profile fails before any provider probe; cloud
login cannot unblock it. The repository's cloud binding stays in place.

JSON output follows the checked-in, versioned
[`status-v3` schema](docs/schemas/status-v3.schema.json). Human and JSON reports
are rendered from the same typed observation; neither includes raw provider
output.

Diagnose local setup without contacting a provider:

```console
authmux doctor
authmux doctor --context crm --json
authmux doctor --context empire --provider ssh
authmux doctor --context crm --provider gcp
```

For AWS, `doctor` requires AWS CLI v2 and compares supported local profile
metadata. For SSH, it checks only configured intent and the installed OpenSSH
client, then warns that remote identity, authorization, MFA state, Session
Usability, and expiry were not observed. For GCP, it locates but never executes
gcloud, checks protected selection metadata independently for the gcloud CLI
and ADC planes, and never opens credential databases or the ADC file.
Mixed-provider contexts require an
explicit `--provider`. Warnings exit successfully; failed checks exit `1`.
`status` and `doctor` are diagnostic and overview commands, not mandatory
preflights for guarded execution.

## Agent continuity

Native providers may renew their own credentials during an explicitly requested
guarded operation. Authmux does not run a refresh timer or background daemon.
When an AWS or GitHub preflight can safely establish that interactive
Reauthentication is required, `exec` exits `10` and writes one compact JSON
event to stderr:

```json
{"schema_version":1,"event":"reauthentication_required","context":"crm","provider":"aws","login_argv":["authmux","login","crm","--provider","aws","--print-command"],"retry":"original_command_once"}
```

The event follows the checked-in
[`exec-event-v1` schema](docs/schemas/exec-event-v1.schema.json). Codex and
Claude preserve the original command, run only the non-executing login preview,
pause for the user's external-terminal login, and retry the exact command once.
They stop on a repeated or malformed event.

Continuity remains provider-specific:

| Provider | Continuity behavior |
|---|---|
| AWS | The native CLI may renew Credentials during the guarded STS preflight. Recognized expired or missing Sessions emit the structured event. Endpoint failures request network access without suggesting Reauthentication. |
| Google Cloud | The gcloud or ADC child owns refresh. Authmux does not capture arbitrary child output or claim that a generic child failure is Reauthentication. |
| GitHub | An unusable provider-validated Session emits the structured event; Reauthentication remains interactive. |
| SSH | OpenSSH owns transport reuse. A keepalive or ControlMaster is not Credential renewal and can lapse independently. |

Deployment and log-monitoring loops expected to outlive a human Session should
run through the repository's approved OIDC or workload-identity path. Authmux
can guard the command that triggers or observes that workflow, but it does not
create static cloud keys or keep a human Session alive indefinitely.

The implemented AWS-first tracer reads a user-owned context, observes the
selected account through the native AWS CLI, refuses an Expected Identity
mismatch, and otherwise creates a process-scoped environment for one child
command. A repository binding may select only a user-defined context; it cannot
override providers or commands, is never discovered above the nearest `.git`
root, and reports its canonical source path through the Config Module. A
matching child preserves its exit code or terminating Unix signal. Google
Cloud `status`, `doctor`, and guarded `exec` are implemented. A native gcloud
child requires matching protected gcloud identity and project metadata; every
other GCP child requires a protected, explicitly declared ADC credential-file
plane. GCP execution does not claim live credential usability before spawn,
and mixed-provider execution remains unsupported. Explicit GCP login delegates
`gcloud auth login` to the selected named configuration with the terminal
attached; it never updates ADC or claims live success from the native exit
alone. Explicit AWS login selects `aws login` or `aws sso login` from bounded
documented profile metadata, follows protected role source-profile chains, and
never reads native credential caches. The AWS `exec` preflight uses
normal AWS CLI credential resolution, which may update AWS-owned caches under
its documented behavior; authmux does not request login or capture the
resulting Credential.

Every executing native login runs at most one selected provider, has no
authmux timeout while the user completes its interactive flow, preserves native
nonzero exits and Unix signals, and never retries or falls through to another
provider. The `--print-command` form starts no provider command. Mixed-provider
Authentication Contexts require `--provider` before either mode produces a
handoff.

Child processes inherit only `PATH`, `HOME`, `LANG`, `LC_ALL`, and `TERM`, plus
the selected provider profile. Credential environment variables and unrelated
parent state are removed. Immediately before spawn, authmux re-reads the
Project Binding and user configuration; a changed context fails closed and
must be retried.

The default suite never contacts AWS. An explicit live gate exercises
`doctor`, `status`, and guarded no-op execution against an isolated temporary
context:

```console
AUTHMUX_LIVE_AWS_PROFILE=crm-development \
AUTHMUX_LIVE_AWS_EXPECTED_ACCOUNT=111111111111 \
AUTHMUX_LIVE_AWS_ACKNOWLEDGE_CACHE_WRITES=1 \
cargo test --test live_aws -- --ignored --exact \
  configured_aws_context_completes_the_live_cli_workflow
```

Use a real non-secret profile name and Expected Identity in place of the
fictional values. The gate requires read-only local identity matching, may
cause the AWS CLI to refresh provider-owned SSO or login caches during the STS
preflight, and removes its temporary authmux configuration. Captured provider
output is not printed by the test.

The interactive recovery gate logs in the first profile, then independently
validates two process-scoped profiles through local status and guarded STS
execution:

```console
AUTHMUX_LIVE_AWS_PROFILE=research-console \
AUTHMUX_LIVE_AWS_EXPECTED_ACCOUNT=111111111111 \
AUTHMUX_LIVE_AWS_SECOND_PROFILE=workload-operator \
AUTHMUX_LIVE_AWS_SECOND_EXPECTED_ACCOUNT=222222222222 \
AUTHMUX_LIVE_AWS_ACKNOWLEDGE_LOGIN_MUTATION=1 \
AUTHMUX_LIVE_AWS_ACKNOWLEDGE_CACHE_WRITES=1 \
cargo test --test live_aws -- --ignored --exact \
  configured_aws_login_and_two_profiles_complete_the_live_workflow
```

The profiles must be distinct, but the gate does not require their Expected
Identities to differ: a role profile can intentionally resolve within the same
account. Native login inherits the terminal and may open a browser. The test
does not capture its authorization URL or input.

The GCP live gate remains local-only and never runs gcloud:

```console
AUTHMUX_LIVE_GCP_CONTEXT=crm \
cargo test --test live_gcp -- --ignored --exact \
  configured_gcp_context_completes_the_live_local_workflow
```

It verifies independent selection observations and doctor checks without
claiming credential usability, refresh, authorization, or expiry.

The separate opt-in execution gate contacts Google Cloud and may let gcloud
refresh or update its native caches:

```console
AUTHMUX_LIVE_GCP_CONTEXT=crm \
AUTHMUX_LIVE_GCP_EXPECTED_PROJECT=fictional-project \
AUTHMUX_LIVE_GCP_ACKNOWLEDGE_CACHE_WRITES=1 \
cargo test --test live_gcp -- --ignored --exact \
  configured_gcp_context_completes_the_live_exec_workflow
```

It runs `gcloud projects describe` through authmux and checks only the expected
project identifier. Provider failure output is intentionally omitted by the
test.

For explicit interactive recovery plus the provider operation, use the
credential-mutating E2E gate:

```console
AUTHMUX_LIVE_GCP_CONTEXT=crm \
AUTHMUX_LIVE_GCP_EXPECTED_PROJECT=fictional-project \
AUTHMUX_LIVE_GCP_ACKNOWLEDGE_LOGIN_MUTATION=1 \
cargo test --test live_gcp -- --ignored --exact \
  configured_gcp_context_completes_the_live_login_and_exec_workflow
```

The native login inherits the terminal and may open a browser. The test does
not capture its output, authorization URL, or input.

The GitHub live gate validates the configured login and runs one read-only API
request through guarded execution:

```console
AUTHMUX_LIVE_GITHUB_CONTEXT=github \
AUTHMUX_LIVE_GITHUB_ACKNOWLEDGE_PROVIDER_CONTACT=1 \
cargo test --test live_github -- --ignored --exact \
  configured_github_context_completes_the_live_cli_workflow
```

It never invokes `gh auth token` or `--show-token`; captured output is not
printed by the test.

Empire AI work begins with an OpenSSH client readiness check that does not read
SSH configuration, inspect an agent, resolve or contact a host, or trigger MFA.
Run its opt-in local gate with:

```console
cargo test --test live_ssh -- --ignored --exact \
  installed_openssh_client_passes_provider_scoped_doctor
```

This proves only that a supported OpenSSH client is installed. The same bounded
check powers `authmux doctor --context empire --provider ssh`; remote identity,
authorization, MFA state, Session Usability, and expiry remain unobserved.

The user configuration remains at
`$XDG_CONFIG_HOME/authmux/config.toml` or `~/.config/authmux/config.toml`.
Empire AI intent can be declared without a Credential or machine-specific key
path:

```toml
version = 1

[contexts.empire]
description = "Empire AI research"

[contexts.empire.providers.ssh]
host_alias = "empire-alpha"
expected_remote_principal = "researcher@example.invalid"
control_path = "/home/researcher/.ssh/sockets/empire-alpha.sock"
```

`host_alias` names user-owned SSH intent; authmux does not evaluate the SSH
configuration behind it. After `authmux login empire --provider ssh` exits
successfully, authmux checks only the protected, explicitly declared local
control socket and reports Transport Reuse as `active`, `inactive`, or
`unknown`; remote identity and Session Usability remain unverified. Google
Cloud selection declares each Credential Plane explicitly; paths are validated
but never printed by status reports:

Agents can fail closed before submitting Empire AI work without starting SSH
or triggering MFA:

```console
authmux status --context empire --provider ssh --require-active-transport
```

This exits `0` only when the protected local ControlMaster is active. An
inactive result exits `1` and instructs the user to run
`authmux login empire --provider ssh`; an unverifiable socket also exits
nonzero. After a successful preflight, agents continue to use native
`ssh empire`, `scp`, and `rsync`.

```toml
[contexts.crm.providers.gcp.gcloud]
config_dir = "/home/researcher/.config/gcloud"
configuration = "crm-research"
expected_principal = "researcher@example.test"
expected_project = "fictional-project"

[contexts.crm.providers.gcp.adc]
mode = "credential_file"
credential_file = "/home/researcher/.config/gcloud/adc/crm.json"
expected_principal = "workload@example.test"
```

Existing AWS-only configuration remains valid. The optional root binding
contains only:

```toml
version = 1

[project]
context = "crm"
```

`.authmux.toml` is ignored by this repository's default because project and
organization names can be sensitive. A project that intentionally shares the
binding must make that decision explicitly.

## Current state

The crate now contains AWS identity guards, independent gcloud CLI and ADC
selection observations, GitHub provider validation and isolated execution, SSH
local transport observation, aggregate all-context status, bounded provider
probes, strict configuration parsing, and isolated child execution. It remains
a development tracer rather than a released CLI. CI runs the same format,
strict lint, test, and locked build gates on pinned Ubuntu and macOS runners.

Start here:

- [workplan.md](workplan.md) — scope, milestones, acceptance criteria, and risk controls
- [CONTEXT.md](CONTEXT.md) — canonical product language
- [AGENTS.md](AGENTS.md) — repository operating contract
- [ADR 0001](docs/adr/0001-delegate-credential-custody.md) — credential-custody decision
- [ADR 0002](docs/adr/0002-separate-status-from-execution-preflight.md) — read-only status boundary
- [ADR 0006](docs/adr/0006-observe-gcp-selection-without-running-gcloud.md) — zero-write GCP observation boundary
- [ADR 0007](docs/adr/0007-guard-gcp-exec-with-local-selection.md) — guarded GCP execution boundary
- [ADR 0008](docs/adr/0008-delegate-gcp-login-to-selected-gcloud-configuration.md) — explicit native GCP login
- [ADR 0009](docs/adr/0009-delegate-aws-login-by-native-profile-mode.md) — explicit native AWS login mode selection
- [ADR 0011](docs/adr/0011-handoff-interactive-login-outside-agent-sessions.md) — external-terminal login handoff
- [ADR 0012](docs/adr/0012-native-refresh-and-resumable-agent-continuity.md) — native refresh and resumable agent continuity
- [Phase 0 evidence](docs/research/2026-08-03-phase-0-evidence.md) — dated competitor and provider findings
- [Build-versus-adopt benchmark](docs/research/2026-08-03-build-vs-adopt-benchmark.md) — pinned Atmos and direnv controls
- [Provider evidence matrix](docs/research/2026-08-03-provider-evidence-matrix.md) — command, selector, side-effect, and sensitivity decisions
- [GCP Phase 2 contract](docs/research/2026-08-03-gcp-phase-2-contract.md) — separate gcloud/ADC planes and mandatory no-write gate
- [Live AWS gate](docs/research/2026-08-03-live-aws-gate.md) — identifier-free evidence for the opt-in real-provider workflow
- [Live GCP gate](docs/research/2026-08-03-live-gcp-gate.md) — local-only real-configuration observation

## License

MIT. See [LICENSE](LICENSE).

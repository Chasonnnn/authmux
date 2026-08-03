# authmux work plan

## 1. Outcome

Build a local-first, open-source CLI that lets one developer answer three
questions reliably across AWS, Google Cloud, GitHub, SSH, and later providers:

1. Which identity will this project use?
2. Is the corresponding native session usable, expired, refreshable, unknown,
   or unreachable?
3. How can I reauthenticate or run one command in the intended context without
   contaminating another project?

The product succeeds when it reduces context mistakes and repetitive login
friction without assuming custody of credentials.

## 2. Product principles

- **Orchestrate; do not vault.** Native tools own credentials and login flows.
- **Project intent is declarative.** A repository names non-secret Provider
  Profiles; it never embeds secrets.
- **Selection is process-scoped.** `authmux exec` affects the child command,
  not unrelated terminals.
- **Uncertainty is honest.** A Provider Adapter may report `unknown` rather
  than fabricate confidence or expiry.
- **Read-only means read-only.** `status` and `doctor` never refresh, switch, or
  log in.
- **Secure defaults are centralized.** One subprocess runner enforces command
  construction, environment policy, timeouts, output limits, and redaction.
- **Useful before broad.** Prove the daily workflow with a small provider set
  before adding a daemon, GUI, team features, or dynamic credentials.

## 3. Initial users and workflows

### Primary user

A developer who works across unrelated organizations and projects on one
machine and already uses the providers' supported CLIs.

### Core workflows

- Enter a repository and see the intended identities plus current status.
- Run a command under the repository's context without changing global state.
- Reauthenticate one expired Provider Profile using the native flow.
- Diagnose a missing CLI, invalid config, unreachable provider, or ambiguous
  identity with a specific next action.
- Review all configured contexts without revealing secret values.

## 4. Scope

### Version 0.1

- One cross-platform Rust binary for macOS and Linux.
- User configuration plus optional repository-local `.authmux.toml`.
- Commands: `status`, `doctor`, `login`, `exec`, `context list`, and
  `context show`.
- Normalized status model with observation time and evidence level.
- Initial Provider Adapters:
  - AWS via supported `aws` profile/session commands; optional integration with
    one external session tool only after a discovery spike.
  - Google Cloud via named `gcloud` configurations.
  - GitHub via `gh` hosts/accounts, with an explicit concurrency decision for
    its global active-account behavior.
  - SSH via agent/key availability and optional connectivity probes.
- Human-readable terminal output and stable JSON output.
- Secret-shaped config rejection and end-to-end redaction tests.

### Explicit non-goals for 0.1

- Storing tokens, passwords, private keys, access keys, or refresh material.
- Implementing OAuth, SAML, OIDC, device authorization, or an identity proxy.
- Replacing Infisical, 1Password, OpenBao, AWS IAM Identity Center, or native
  keychains.
- Background refresh, a daemon, cloud synchronization, team RBAC, approval
  workflows, a GUI, or a hosted control plane.
- SSH certificate issuance or a general-purpose SSH connection manager.
- Automatic discovery of every account on the machine.
- Mutating a provider's global active identity during `exec` unless the user
  explicitly opts into a documented, serialized fallback.

## 5. Canonical domain model

The terms in `CONTEXT.md` are normative. The initial model is:

```text
Project Binding
    -> Authentication Context
         -> one or more Provider Profiles
              -> Provider-owned Session
                   -> Status Observation
                        -> Validity State

Authentication Context
    -> Execution Scope
         -> child command
```

A context contains references and display metadata only. A Status Observation
records `provider`, `profile`, `observed_at`, `state`, `evidence_level`, an
optional provider-reported expiration, and a sanitized next action. It never
contains raw provider output or a Credential.

## 6. Proposed command contract

```console
authmux status [--context NAME] [--json]
authmux doctor [--context NAME] [--json]
authmux login <context> [--provider NAME]
authmux exec <context> -- <program> [args...]
authmux context list [--json]
authmux context show <name> [--json]
```

Behavioral rules:

- Repository binding is used when `--context` is omitted; ambiguity is an
  error, not an interactive guess.
- `status` reports observations and exits nonzero only for command/config
  failure. Individual invalid sessions remain data in the report.
- `doctor` checks config, executable discovery, supported CLI versions, and
  safe provider reachability without changing authentication state.
- `login` shows exactly which Provider Profile will be affected and delegates
  to its native flow.
- `exec` resolves one context, builds a minimal child environment, and uses an
  argument vector. It forwards the child's exit code and signals.
- `--json` has a versioned schema and contains sanitized structured data only.

## 7. Configuration sketch

The final schema is a Phase 1 deliverable; this sketch defines the security
and usability constraints, not a frozen contract.

```toml
version = 1

[contexts.crm]
description = "CRM project"

[contexts.crm.providers.aws]
profile = "crm-development"

[contexts.crm.providers.gcp]
configuration = "crm"

[contexts.crm.providers.github]
host = "github.com"
identity = "work-handle"

[project]
context = "crm"
```

Configuration layers, from lowest to highest precedence:

1. User config defines reusable Authentication Contexts.
2. Repository config binds the project to a context and may narrow non-secret
   selectors.
3. Explicit CLI flags select a context for one invocation.

The loader must report the source of every resolved field, reject unknown or
secret-shaped keys, avoid environment-variable interpolation, and never search
parent directories beyond the repository root.

## 8. Module design

### Context engine

A deep Module that loads configuration, resolves one Authentication Context,
normalizes observations, and plans login or execution. Its Interface accepts
typed config sources and Provider Adapter results; it returns typed plans and
reports. It does not execute provider commands directly.

### Provider registry

Maps a provider name to a Provider Adapter. Each Adapter hides executable
discovery, supported command variants, narrow parsing, native login arguments,
and process-scoped selectors. The Interface should remain small:

```text
capabilities() -> ProviderCapabilities
observe(profile, probe_policy) -> StatusObservation
login_plan(profile) -> InteractiveCommand
execution_selection(profile) -> ExecutionSelection
```

The test Adapter is the second implementation at this Seam. It supplies
deterministic outcomes without invoking real CLIs.

### Secure process runner

The only Module allowed to spawn processes. It accepts an executable and
argument vector, an environment policy, timeout, output limit, and interaction
mode. It returns bounded bytes plus exit metadata. Redaction occurs before
diagnostics cross the Interface.

### Config Module

Loads versioned TOML into typed, validated structures; tracks field provenance;
and rejects secrets. File discovery and merging remain private implementation
details.

### Presentation Module

Renders human and JSON reports from the same typed results. JSON schemas are
golden-tested and versioned. ANSI styling never enters structured output.

### CLI shell

Parses arguments, calls the modules above, maps typed results to exit codes,
and owns terminal interaction. Business and security policy must not accumulate
in command handlers.

## 9. Status semantics

Each Provider Adapter maps native evidence to exactly one state:

| State | Meaning | Typical next action |
|---|---|---|
| `valid` | Provider evidence supports current usability | None |
| `expired` | Provider explicitly reports an expired session | Run `login` |
| `refreshable` | Native tooling reports it can refresh under its own rules | Run explicit refresh/login |
| `unknown` | Available evidence cannot determine validity | Run a provider-specific probe |
| `unreachable` | A bounded probe could not reach required local/remote state | Fix connectivity or CLI setup |
| `not_applicable` | The identity does not have an expiring session | Check availability/connectivity only |

Every observation also declares an evidence level:

- `local_metadata`: no remote authorization was exercised.
- `provider_validation`: a supported read-only provider command succeeded.
- `connectivity_only`: presence or connection was observed without identity
  authorization proof.

## 10. Security design and threat checklist

### Protected assets

- Provider credentials and cache contents.
- Identity, organization, project, host, and repository metadata.
- The integrity of the command and environment selected for execution.

### Primary threats

- Secrets leaking through logs, JSON, errors, crash reports, or fixtures.
- Shell injection or argument confusion in delegated commands.
- Environment inheritance selecting an unintended identity.
- Malicious provider output injecting terminal escapes or oversized data.
- TOCTOU changes between status observation and command execution.
- Concurrent commands racing on provider-global active-account state.
- A compromised repository config selecting an unexpected identity or binary.
- False confidence from stale local metadata.

### Required controls

- Argument-vector process execution and executable allowlisting/discovery.
- Minimal environment construction with an explicit inheritance policy.
- Output caps, timeouts, control-character handling, and redaction.
- Config trust messaging and an inspectable resolution report.
- No executable paths or arbitrary commands from repository config.
- Observation timestamps and evidence levels in every report.
- Re-resolution immediately before `exec`; warn or fail on material drift.
- Serialized or forbidden flows for provider-global mutation.
- Property and fixture tests that seed token-like values into every output path.

## 11. Milestones

### Phase 0 — evidence and feasibility

Deliverables:

- [ ] Inventory the installed versions and supported non-secret status/login
  commands for `aws`, `gcloud`, `gh`, and `ssh-add`.
- [ ] Record redacted command-output fixtures for success, expiry, missing
  login, missing executable, timeout, malformed output, and unreachable
  service.
- [ ] Confirm which selectors can be applied per process and which mutate
  global state.
- [ ] Compare AWS native profiles, IAM Identity Center, Granted, and aws-vault;
  select only one optional external-tool path for 0.1.
- [ ] Resolve the GitHub multi-account concurrency strategy.
- [ ] Validate the proposed status states against real provider evidence.
- [ ] Create the Rust crate, CI, formatting, linting, and test harness under the
  pinned toolchain.

Exit criteria:

- Every initial provider has an evidence matrix with commands, side effects,
  output sensitivity, timeouts, and known uncertainty.
- No required 0.1 workflow depends on reading raw credential caches.
- Hard architectural decisions are accepted as ADRs.
- The empty crate passes format, clippy, test, and locked build checks on macOS
  and Linux.

### Phase 1 — configuration, domain, and read-only status

Deliverables:

- [ ] Implement typed domain states and evidence levels with exhaustive tests.
- [ ] Implement user/repository config discovery, versioning, merging,
  provenance, and validation.
- [ ] Reject secret-shaped fields and values with redaction-safe errors.
- [ ] Implement the secure process runner with deterministic test execution.
- [ ] Implement `context list`, `context show`, `status`, and `doctor`.
- [ ] Add AWS and Google Cloud Provider Adapters from Phase 0 evidence.
- [ ] Add stable JSON schemas and terminal golden tests.

Exit criteria:

- A repository resolves to the intended context with explainable provenance.
- Status across AWS and Google Cloud reports partial failures without hiding
  successful observations.
- Running read-only commands cannot change native provider state.
- Token-like test data never appears in snapshots, errors, or JSON.
- Default tests run without real accounts or credential caches.

### Phase 2 — isolated execution

Deliverables:

- [ ] Implement `exec` with child-only selectors, signal forwarding, and exact
  exit-code propagation.
- [ ] Define and test the environment inheritance allowlist.
- [ ] Re-resolve the context immediately before process spawn.
- [ ] Add GitHub and SSH Provider Adapters with their documented evidence
  limitations.
- [ ] Refuse unsafe global switching by default.
- [ ] Add cross-context concurrency tests and hostile argument tests.

Exit criteria:

- Two simultaneous commands can target different safe contexts without
  contaminating each other.
- The child sees only the intended selectors and allowed inherited variables.
- Spaces, Unicode, leading dashes, and shell metacharacters remain literal
  arguments.
- Signals and exit codes match direct execution.

### Phase 3 — explicit reauthentication

Deliverables:

- [ ] Implement `login` plans for initial providers.
- [ ] Preview the affected Provider Profile and native command before mutation.
- [ ] Support interactive terminal handoff without capturing secrets.
- [ ] Re-observe status after successful login and display evidence.
- [ ] Handle cancellation, timeout, native failure, and partial multi-provider
  completion without silent retry.

Exit criteria:

- Login never runs from `status`, `doctor`, or `exec` implicitly.
- Interactive secrets bypass authmux capture and logging.
- Cancellation leaves other contexts untouched.
- The post-login report distinguishes native command success from validated
  session usability.

### Phase 4 — hardening and dogfood release

Deliverables:

- [ ] Run a dedicated security review and threat-model update.
- [ ] Add fuzz/property tests for config, provider parsers, redaction, and
  terminal output.
- [ ] Add shell completions, man page, install/uninstall instructions, and a
  config migration guide.
- [ ] Package signed checksummed binaries for macOS arm64/x64 and Linux x64.
- [ ] Add opt-in diagnostics that are inspectable and sanitized.
- [ ] Dogfood across at least two unrelated organizations and four real
  projects for two weeks.

Exit criteria:

- No high-severity security findings remain open.
- A fresh machine can install, configure, diagnose, and remove authmux using
  the documented path.
- Dogfood notes show whether context errors or reauthentication friction
  decreased; failures include reproducible evidence.
- The project passes the go/no-go criteria in section 14.

### Phase 5 — public OSS readiness

Deliverables:

- [ ] Scan full Git history and release artifacts for secrets and identifying
  internal metadata.
- [ ] Replace real fixtures with fictional equivalents and verify parity.
- [ ] Add `SECURITY.md`, `CONTRIBUTING.md`, code of conduct, support policy,
  changelog, and vulnerability-reporting route.
- [ ] Document provider trademarks, supported versions, limitations, and
  compatibility policy.
- [ ] Configure public CI with least-privilege tokens and dependency/license
  scanning.
- [ ] Obtain an external security review of credential and subprocess paths.

Exit criteria:

- Public clone, build, test, and install succeed without private dependencies.
- Secret/history scanning is clean.
- Security disclosure and maintenance expectations are explicit.
- Repository visibility changes only after owner approval.

## 12. Verification matrix

| Area | Required evidence |
|---|---|
| Config | unit, merge/provenance, schema golden, secret-rejection tests |
| Domain | exhaustive state mapping and invalid-transition tests |
| Process runner | hostile args, env filtering, timeout, output cap, signals |
| Redaction | seeded secrets across success, failure, JSON, terminal, panic paths |
| Provider Adapter | redacted contract fixtures plus opt-in read-only integration |
| `status` / `doctor` | no-side-effect assertion and partial-failure behavior |
| `exec` | cross-context isolation, child exit/signal parity, drift detection |
| `login` | explicit preview, terminal passthrough, cancel/failure behavior |
| Packaging | clean-machine install, checksum/signature, uninstall |
| OSS gate | history scan, fictional fixtures, public CI, security review |

## 13. Key decisions still open

Resolve these with evidence during Phase 0; create an ADR only when the choice
is hard to reverse, surprising, and a real trade-off.

- CLI framework and async runtime, if any.
- Exact user and project config locations and precedence.
- GitHub multi-account strategy when `gh` requires global active state.
- AWS external-session-tool support: none, Granted, or aws-vault.
- Whether SSH remote probes belong in 0.1 or agent inspection is sufficient.
- JSON schema versioning and exit-code taxonomy.
- Distribution channels beyond release binaries.

## 14. Go/no-go economics

Continue beyond the dogfood release only if the two-week trial demonstrates at
least two of these outcomes:

- It prevents or catches a real wrong-account or wrong-project action.
- It removes repeated manual status/login steps on most active workdays.
- Project onboarding becomes materially simpler than provider-specific notes.
- The same core model works for at least three providers without provider
  details leaking through the Interface.

Pause or narrow the project if:

- Native tooling plus shell aliases solves the observed workflow with similar
  reliability.
- Status remains mostly `unknown`, making the dashboard misleading.
- Safe execution requires routine global provider mutation.
- Maintenance tracks provider CLI churn more than user value.
- Security review finds that orchestration meaningfully increases credential
  exposure.

Recommended investment cap before this gate: a focused prototype and dogfood
cycle, not a hosted product or team platform.

## 15. Risk register

| Risk | Impact | Mitigation | Trigger to revisit |
|---|---|---|---|
| Provider output changes | False status or parser failure | narrow parsers, version matrix, fixtures, explicit `unknown` | upstream CLI release breaks contract tests |
| Global identity mutation | Cross-project contamination | process selectors; reject or serialize fallback | provider lacks safe selector |
| Secret leakage | Credential compromise | central runner/redactor, hostile fixtures, no raw cache reads | any sensitive value reaches output |
| Misleading validity | Unsafe operator confidence | evidence levels, timestamps, honest uncertainty | local and remote evidence diverge |
| Config from untrusted repo | Wrong identity or command | no commands/paths in project config, inspectable resolution | config influences executable selection |
| Scope expansion | Poor return on maintenance | non-goals and dogfood economics gate | daemon, GUI, or team request before 0.1 proof |
| Provider maintenance burden | Unsustainable project | small Adapter Interface, documented support matrix | repeated breakage across releases |

## 16. Definition of done for each slice

A slice is complete only when:

- its observable behavior is expressed by a failing test first;
- implementation passes focused and affected full-suite checks;
- security-negative paths are tested where credentials, subprocesses,
  configuration, or provider output are involved;
- human and JSON output are sanitized and consistent;
- canonical docs and help output match behavior;
- temporary fixtures and processes are removed;
- the worktree is clean and local/remote parity is verified after delivery.

## 17. Immediate next slice

Begin Phase 0 with a read-only evidence collector document—not product code—for
the four initial providers. For each command, record supported CLI version,
arguments, side effects, exit codes, stdout/stderr sensitivity, timeout,
evidence level, and whether selection is process-scoped. Use only fictional or
redacted results in the repository.

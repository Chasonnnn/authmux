# authmux work plan

## 1. Outcome

Build a local-first, open-source CLI that lets one developer answer three
questions reliably across AWS, Google Cloud, and later providers:

1. Does the observed identity match the identity this project expects?
2. Is the corresponding native session usable, and what evidence supports that
   conclusion?
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
  - AWS via supported `aws` profile/session commands.
  - Google Cloud after the AWS vertical slice proves the Interface, with gcloud
    CLI configuration and Application Default Credentials treated as separate
    credential planes and observed independently.
- Evidence-only feasibility notes for GitHub. Empire AI enters 0.1 through
  bounded OpenSSH local readiness and explicit native SSH login delegation; it
  gains no remote status or execution selection unless a later gate proves
  those behaviors without copying credentials, executing user configuration
  from a read-only command, or mutating global state.
- Human-readable terminal output and stable JSON output.
- Secret-shaped config rejection and end-to-end redaction tests.

### Explicit non-goals for 0.1

- Storing tokens, passwords, private keys, access keys, or refresh material.
- Implementing OAuth, SAML, OIDC, device authorization, or an identity proxy.
- Replacing Infisical, 1Password, OpenBao, AWS IAM Identity Center, or native
  keychains.
- Background refresh, a daemon, cloud synchronization, team RBAC, approval
  workflows, a GUI, or a hosted control plane.
- SSH certificate issuance or a general-purpose SSH connection manager;
  user-owned OpenSSH multiplexing may be used by explicit native login.
- GitHub or SSH execution selection without a provider-supported,
  process-scoped mechanism.
- `shell`, generic logout or revocation, automatic identity discovery, external
  Provider Adapter plugins, or arbitrary environment-selector maps.
- Generated `GIT_SSH_COMMAND`, first-class `KUBECONFIG`, or any command that
  prints or exports a Credential for authmux to relay.
- Automatic discovery of every account on the machine.
- Mutating a provider's global active identity during `exec` unless the user
  explicitly opts into a documented, serialized fallback.

## 5. Canonical domain model

The terms in `CONTEXT.md` are normative. The initial model is:

```text
Project Binding
    -> Authentication Context
         -> one or more Provider Profiles + Expected Identities
              -> Provider-owned Session
                   -> Status Observation
                        -> Observed Identity + Identity Match
                        -> Session Usability + Observation Reason
                        -> Reauthentication Need + Evidence Level

Authentication Context
    -> Execution Scope
         -> child command
```

A context contains references, Expected Identities, and display metadata only.
A Status Observation records `provider`, `profile`, `observed_at`,
`observed_identity`, `identity_match`, `usability`, `reason`,
`reauthentication_need`, `evidence_level`, an optional provider-reported
expiration, and a sanitized next action. It never contains raw provider output
or a Credential.

## 6. Proposed command contract

```console
authmux status [--context NAME] [--provider NAME] [--json]
authmux doctor [--context NAME] [--provider NAME] [--json]
authmux login <context> [--provider NAME]
authmux exec [--context NAME] -- <program> [args...]
authmux context list [--json]
authmux context show [--context NAME]
```

Behavioral rules:

- Repository binding is used when `--context` is omitted; ambiguity is an
  error, not an interactive guess.
- `status` reports observations and exits nonzero only for command/config
  failure. Individual invalid sessions remain data in the report. SSH status
  observes only an explicitly configured local control socket per ADR 0005.
- `doctor` checks config, executable discovery, supported CLI versions, and
  only provider observations already proven read-only. AWS and SSH checks do
  not contact their providers. A mixed-provider context requires an explicit
  `--provider`. Warnings exit `0`; failed checks exit `1`.
- `login` shows exactly which Provider Profile will be affected and delegates
  to its native flow. SSH login evaluates user-owned OpenSSH configuration only
  after this preview; authmux neither configures nor promises connection reuse.
- `exec` resolves one context, builds a minimal child environment, and uses an
  argument vector. It forwards the child's exit code and signals.
- `--json` has a versioned schema and contains sanitized structured data only.

## 7. Configuration sketch

The schema is versioned and remains pre-1.0. The current tracer accepts optional
AWS, SSH, and Google Cloud Provider Profiles, optional context descriptions,
and the restricted repository binding. Google Cloud models gcloud CLI and ADC
as separate Credential Planes. Existing version 1 configuration requires no
migration.

```toml
version = 1

[contexts.crm]
description = "CRM project"

[contexts.crm.providers.aws]
profile = "crm-development"
expected_account = "123456789012"

[contexts.empire.providers.ssh]
host_alias = "empire-alpha"
expected_remote_principal = "researcher@example.invalid"
control_path = "/home/researcher/.ssh/controlmasters/empire-alpha.sock"

[contexts.crm.providers.gcp.gcloud]
config_dir = "/absolute/user-owned/gcloud-config-root"
configuration = "crm"
expected_principal = "developer@example.invalid"

[contexts.crm.providers.gcp.adc]
mode = "credential_file"
credential_file = "/absolute/user-owned/credential-config.json"
expected_principal = "service-account@example.invalid"

```

Repository configuration contains only the binding:

```toml
version = 1

[project]
context = "crm"
```

Configuration layers, from lowest to highest precedence:

1. User config defines reusable Authentication Contexts.
2. Repository config may only bind the project to a user-defined context; it
   cannot define or override Provider Profiles or Expected Identities.
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

Each Status Observation reports orthogonal conclusions instead of forcing
provider evidence into one overloaded state:

| Axis | Values | Meaning |
|---|---|---|
| Session Usability | `usable`, `unusable`, `indeterminate` | Whether current use is supported by evidence |
| Identity Match | `match`, `mismatch`, `unverified` | Whether observed and expected identities agree |
| Reauthentication Need | `required`, `not_required`, `unknown`, `not_applicable` | Whether an explicit native flow is needed |
| Observation Reason | provider-neutral typed reason or none | Why the conclusion was reached |

Every observation also declares one evidence level:

- `local_metadata`: no remote authorization was exercised.
- `provider_validation`: a supported read-only provider command succeeded.
- `connectivity_only`: presence or connection was observed without identity
  authorization proof.

Expiration is optional and may be reported only when a supported native command
exposes it without printing a Credential. None of the initial Adapter evidence
currently justifies promising an exact countdown.

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
- Minimal environment construction with a user-owned inheritance allowlist;
  production inherits only `PATH`, `HOME`, `LANG`, `LC_ALL`, and `TERM`, and
  repository configuration cannot add inherited variable names.
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

- [x] Inventory the installed versions and supported non-secret status/login
  commands for `aws`, `gcloud`, `gh`, and `ssh-add`.
- [x] Record redacted command-output fixtures for success, expiry, missing
  login, missing executable, timeout, malformed output, and unreachable
  service.
- [x] Confirm which selectors can be applied per process and which mutate
  global state.
- [ ] Prove native AWS profiles and modern IAM Identity Center behavior,
  including concurrent profiles that share one SSO session; add no first-class
  external AWS session-tool integration in 0.1.
- [x] Execute the opt-in live AWS gate for one user-owned profile without
  retaining provider identifiers or raw output.
- [x] Compare the fictional AWS mismatch workflow against Atmos and against a
  `direnv` plus native-CLI control, using Granted for AWS where it is already
  configured; record versioned build-vs-adopt evidence.
- [ ] Test the GitHub hypothesis of pre-provisioned, user-owned
  `GH_CONFIG_DIR` directories, secure credential-store failure, and Git helper
  behavior without switching a shared active account or extracting a token.
- [x] Treat gcloud CLI authentication and ADC as separate evidence surfaces;
  run the synthetic command-purity gate without reading or printing
  credentials; record the failed zero-write result in ADR 0006.
- [x] Record the user-only two-plane GCP schema, selector policy, prohibited
  operations, and synthetic no-write implementation gate.
- [x] Limit SSH evidence to local readiness in 0.1; do not infer remote
  identity, MFA state, authorization, or expiry from agent inspection.
- [ ] Validate the proposed status states against real provider evidence.
- [x] Create the Rust crate, CI, formatting, linting, and test harness under the
  pinned toolchain.

Exit criteria:

- Every initial provider has an evidence matrix with commands, side effects,
  output sensitivity, timeouts, and known uncertainty.
- No required 0.1 workflow depends on reading raw credential caches.
- The evidence matrix rejects credential-export and token-printing commands,
  generated `GIT_SSH_COMMAND`, and unverified exact-expiry claims.
- The Atmos and `direnv` control runs establish whether authmux's identity guard
  adds value beyond existing tooling.
- Hard architectural decisions are accepted as ADRs.
- The empty crate passes format, clippy, test, and locked build checks on macOS
  and Linux.

### Phase 1 — AWS identity-guard vertical slice

Deliverables:

- [x] Implement typed identity comparison, usability, reasons,
  reauthentication need, and evidence levels with exhaustive tests.
- [x] Implement user/repository config discovery, versioning, merging,
  provenance, and validation.
- [x] Reject secret-shaped fields and values with redaction-safe errors.
- [x] Implement the secure process runner with deterministic test execution.
- [x] Implement `context show`, provider-free `context list`, and guarded
  `exec` for one AWS Authentication Context.
- [x] Implement read-only `status` using a local-metadata observation contract,
  not the cache-refreshing execution preflight.
- [x] Add the AWS Provider Adapter from Phase 0 evidence.
- [x] Add read-only `doctor` checks for config, AWS CLI v2, and local profile
  identity metadata.
- [x] Add stable status, context-list, and doctor JSON schemas plus terminal
  golden tests.

Exit criteria:

- A repository resolves to the intended context with explainable provenance.
- A mismatched observed AWS account prevents child execution with a sanitized,
  actionable failure.
- A matching AWS account runs the child with process-scoped selection and exact
  exit-code and signal behavior.
- Running read-only commands cannot change native provider state.
- Token-like test data never appears in snapshots, errors, or JSON.
- Default tests run without real accounts or credential caches.

### Phase 2 — Google Cloud and multi-provider isolation

Deliverables:

- [ ] Generalize `exec` from the proven AWS slice to multiple Provider Profiles.
- [x] Add guarded GCP-only execution with command-sensitive gcloud and ADC
  plane requirements, material pre-spawn re-resolution, sanitized failures,
  and child exit/signal parity. Keep live usability delegated to the explicit
  child and reject mixed-provider composition under ADR 0007.
- [x] Define and test the environment inheritance allowlist.
- [x] Re-resolve the context immediately before process spawn and fail closed
  if the Project Binding, Provider Profile, or Expected Identity changed.
- [x] Add the Google Cloud Provider Adapter with independent gcloud CLI and ADC
  observations for every declared credential plane. The disposable,
  network-denied command-purity gate failed, so ADR 0006 prohibits gcloud
  subprocesses and credential-database reads from `status` and `doctor`.
- [x] Add a bounded OpenSSH client readiness Module as the first Empire AI
  local-readiness slice; keep remote identity, MFA, authorization, expiry, and
  execution selection explicitly unsupported.
- [x] Add user-owned Empire AI host alias and Expected Identity configuration
  with provider-free context inspection.
- [x] Expose OpenSSH readiness through provider-scoped `doctor` without
  evaluating SSH configuration or contacting the cluster; keep `exec`
  unsupported until stronger remote evidence and a safe Execution Scope exist.
- [x] Add local SSH transport status through an explicit protected control
  socket without evaluating SSH configuration or contacting the provider;
  keep Identity Match unverified and Session Usability indeterminate.
- [x] Delegate explicit SSH login to `ssh HOST_ALIAS` with terminal passthrough,
  filtered environment inheritance, and no capture of MFA input or native
  output; leave `ControlMaster` and `ControlPersist` under user-owned OpenSSH
  configuration per ADR 0004.
- [ ] Refuse unsafe global switching by default.
- [x] Add cross-context concurrency tests and hostile argument tests.

Exit criteria:

- Two simultaneous commands can target different safe contexts without
  contaminating each other.
- A successful gcloud CLI observation never implies that SDK ADC is usable or
  resolves to the same identity.
- The child sees only the intended selectors and allowed inherited variables.
- Spaces, Unicode, leading dashes, and shell metacharacters remain literal
  arguments.
- Signals and exit codes match direct execution.

### Phase 3 — explicit reauthentication

Deliverables:

- [x] Implement `login` plans for all initial providers: AWS, GCP, and SSH.
- [x] Delegate explicit AWS Reauthentication to `aws login` or `aws sso login`
  from bounded local profile metadata, including guarded source-profile
  traversal for selected role profiles under ADR 0009.
- [x] Delegate explicit GCP user reauthentication to `gcloud auth login` under
  the selected named configuration, with a direct terminal, no ADC mutation,
  and material pre-spawn revalidation under ADR 0008.
- [x] Preview the affected SSH Provider Profile and native command before
  mutation.
- [x] Support SSH interactive terminal handoff without capturing secrets.
- [x] Re-observe protected local SSH Transport Reuse after successful native
  login and display the result without claiming remote Session Usability.
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
- Whether pre-provisioned `GH_CONFIG_DIR` directories remain safely isolated
  when the OS credential store is unavailable and when Git uses `gh` as a
  credential helper.
- Whether a user-owned ADC reference has portable, process-scoped behavior
  across the supported Google client libraries.
- Remaining exit-code taxonomy for login and partial multi-provider failure.
- Distribution channels beyond release binaries.

## 14. Go/no-go economics

Continue beyond the dogfood release only if the two-week trial demonstrates at
least two of these outcomes:

- It prevents or catches a real wrong-account or wrong-project action.
- It removes repeated manual status/login steps on most active workdays.
- Project onboarding becomes materially simpler than provider-specific notes.
- The same core model works for at least two providers without provider
  details leaking through the Interface.

Pause or narrow the project if:

- Atmos or `direnv` plus native tooling solves the observed workflow with
  similar reliability and acceptable custody/trust behavior.
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
| Duplicate existing product | Low incremental user value | benchmark the same workflow against Atmos and a native-tool control | identity guard is not materially safer or simpler |
| Secret leakage | Credential compromise | central runner/redactor, hostile fixtures, no raw cache reads | any sensitive value reaches output |
| Misleading validity | Unsafe operator confidence | evidence levels, timestamps, honest uncertainty | local and remote evidence diverge |
| Config from untrusted repo | Wrong identity or command | no commands/paths in project config, inspectable resolution | config influences executable selection |
| Scope expansion | Poor return on maintenance | non-goals and dogfood economics gate | daemon, GUI, or team request before 0.1 proof |
| Provider maintenance burden | Unsustainable project | small Adapter Interface, documented support matrix | repeated breakage across releases |
| Credential-plane confusion | Wrong GCP identity in SDKs | observe gcloud CLI and ADC independently | a child uses an undeclared or unverified plane |

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

The fictional AWS tracer proves fail-closed mismatch behavior, matching
process-scoped execution with exit-code and Unix-signal parity, and root-bounded
Project Binding discovery. The Atmos and `direnv` comparison and provider
command matrix are complete. Implement `context show` next because it can
explain intent and provenance without touching provider state. Keep `status`
blocked on a separate local-metadata observation contract; do not reuse the
potentially cache-refreshing `exec` preflight.

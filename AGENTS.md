# authmux agent rules

This is the repository operating contract for every human and coding agent.
It generalizes the durable practices from the Surrogacy Force and AI-Ready
Workforce repositories for a security-sensitive, local-first CLI.

## Orientation and sources of truth

Read in this order before changing behavior:

1. `AGENTS.md` for repository policy.
2. `CONTEXT.md` for canonical product language.
3. Accepted decisions in `docs/adr/`.
4. `workplan.md` for current scope, sequencing, and acceptance criteria.
5. Live code, tests, manifests, and generated help output.

Live behavior and tests supersede plans. When they disagree with canonical
documentation, stop and identify the discrepancy; do not silently choose one.
Use primary sources—official provider documentation, CLI help, and upstream
repositories—for provider behavior. State assumptions when evidence is
missing.

## Product boundary

`authmux` coordinates authentication contexts. It does not become a credential
vault, identity provider, OAuth broker, secret synchronizer, or authorization
system.

Never:

- store, copy, print, serialize, index, transmit, or commit credentials;
- parse native credential cache files when a supported status command exists;
- log raw provider stdout/stderr without an explicit redaction layer;
- silently switch a user's global provider identity;
- claim a session is valid when the provider only exposed local metadata;
- execute a login or other state-changing provider command from `status` or
  `doctor`;
- interpolate a user command through a shell;
- add telemetry that can identify providers, organizations, projects,
  usernames, roles, hosts, or repository paths without explicit approval.

Repository examples and fixtures use fictional identities only. `.authmux.toml`
contains non-secret references but is ignored by default because organization
and project names can still be sensitive.

## Operating contract

- Translate the request into verifiable outcomes before implementation.
- Ask only when an unresolved answer materially changes scope, architecture,
  security posture, or a data contract; batch related questions.
- Prefer the smallest coherent change. Do not add speculative providers,
  abstractions, compatibility layers, or configuration.
- Every changed line must trace to the task. Preserve unrelated user work.
- If a simpler approach satisfies the same outcome, recommend it and explain
  the trade-off.
- Record deviations from the agreed plan or an accepted ADR; never adapt
  silently.
- Do not describe an implementation or milestone as complete without executed
  evidence for its acceptance criteria.

## Architecture

Favor deep modules: a small Interface should hide substantial provider or
execution complexity. Use these terms precisely in design discussions:

- **Module**: implementation plus its Interface.
- **Interface**: what callers depend on; also the primary test surface.
- **Seam**: the point where one module can be replaced or isolated.
- **Adapter**: a provider-specific implementation behind a real Seam.

The core owns normalized domain behavior. Provider-specific command discovery,
status parsing, login invocation, and selector construction stay inside each
Provider Adapter. Do not leak raw CLI output or provider-specific states into
the core Interface.

One production Adapter plus a deterministic test Adapter justifies a Seam.
Tests assert observable outcomes through the Interface, not internal process
calls. Keep subprocess execution behind one narrow runner so timeouts,
environment filtering, output limits, and redaction are enforced consistently.

## Security invariants

- Child commands receive an allowlisted environment plus the selectors needed
  for the chosen Authentication Context. They do not inherit arbitrary secret
  variables by accident.
- Commands are spawned with an argument vector, never `sh -c` or equivalent.
- Status probes are read-only, bounded by a timeout, and capped in output size.
- Provider stdout and stderr are untrusted inputs. Parse narrowly, redact
  before diagnostics, and return typed failures.
- Session Usability, Observation Reason, Reauthentication Need, Identity Match,
  and Evidence Level remain distinct; adapters do not collapse them into one
  overloaded status.
- Never infer an expiration time. Preserve provider-reported provenance and
  observation time.
- Login is explicit, interactive when the provider requires it, and uses the
  provider's supported command.
- Configuration rejects secret-shaped fields and values; tests cover this
  negative path.
- Error messages are actionable but must not expose tokens, key material,
  signed URLs, cookie values, or full sensitive paths.

Security-sensitive changes require negative tests and a review of every path
that can display, persist, or pass provider output.

## Configuration and compatibility

Project configuration is declarative and non-secret. Prefer process-scoped
selection over global mutable state. If a provider only supports global
selection, expose the limitation and serialize or reject unsafe concurrent
operations.

The project is pre-1.0. Breaking simplifications are acceptable, but config
schema changes must fail clearly and update examples, validation, and migration
notes in the same change. Do not add automatic compatibility fallbacks.

## Toolchain

`/Users/chason/.config/mise/config.toml` is the approved global baseline. Keep
the repository's `mise.toml` and `mise.lock` aligned with it. Rust dependencies
are locked in `Cargo.lock`; do not use floating tool selectors.

Once the Rust crate exists, use the repository commands:

```bash
mise install
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --locked
```

Reuse checked-in scripts or Make targets when they exist rather than
duplicating their implementation in Mise tasks.

## Test-driven development

For features and bug fixes, write or update a failing behavior test first,
then implement the minimum coherent change and refactor while green.

The test layers are:

- domain tests for normalization and policy without I/O;
- module-interface tests using deterministic fake process results;
- provider contract fixtures captured from fictional, redacted output;
- opt-in integration tests against installed CLIs, read-only by default;
- end-to-end tests in disposable accounts only after explicit authorization.

Never require a developer's real credential cache for the default test suite.
A test must fail if sensitive-looking output reaches logs, snapshots, reports,
or error strings.

Scale verification to blast radius. Provider, config, subprocess, logging, and
security changes require the full affected suite plus negative tests.

## Failure behavior

No silent fallbacks. Return an explicit, typed, sanitized failure with a next
action. Retrying must not broaden scope or switch identity. Partial provider
failure must not erase successful observations from other providers.

## Git and delivery

- Do not create a branch or pull request unless the user explicitly asks.
- Use conventional commit prefixes: `feat:`, `fix:`, `docs:`, `refactor:`,
  `test:`, or `chore:`.
- Keep one logical change group per commit and include reviewer-relevant
  context in the commit body.
- Do not add AI attribution, session trailers, or generated-by messages.
- Update the owning canonical document in the same commit when a decision,
  invariant, scope, or milestone changes.
- Before pushing, inspect the staged file list, run the relevant checks, and
  verify the worktree is clean and local/remote commits match afterward.

The repository is private during early development but MIT licensed. Before a
public release, perform the OSS-readiness gate in `workplan.md`; privacy must
never be treated as a substitute for secret hygiene.

## Runtime hygiene

Start external CLIs, local servers, browser sessions, or monitoring processes
only for an active verification step. Record ownership and process IDs; stop
everything started for the task and verify it exited. Never stop an inherited
process until its project and owner are known. Remove temporary test artifacts
before handoff and report anything intentionally left running.

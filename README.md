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

Inspect documented local AWS profile metadata without contacting AWS or
refreshing a Session:

```console
authmux status
authmux status --context crm
authmux status --context crm --json
```

This status can detect whether an IAM Identity Center profile's configured
account or an AWS login profile's `login_session` account matches the Expected
Identity. It retains only the account segment of supported AWS ARNs. It always
reports Session Usability as `indeterminate`; use guarded `exec` when
provider-validated identity evidence is required.

JSON output follows the checked-in, versioned
[`status-v1` schema](docs/schemas/status-v1.schema.json). Human and JSON reports
are rendered from the same typed observation; neither includes raw provider
output.

Diagnose local setup without contacting AWS:

```console
authmux doctor
authmux doctor --context crm --json
```

`doctor` checks configuration, requires AWS CLI v2, and compares supported
local profile metadata. Warnings exit successfully; failed checks exit `1`.

The implemented AWS-first tracer reads a user-owned context, observes the
selected account through the native AWS CLI, refuses an Expected Identity
mismatch, and otherwise creates a process-scoped environment for one child
command. A repository binding may select only a user-defined context; it cannot
override providers or commands, is never discovered above the nearest `.git`
root, and reports its canonical source path through the Config Module. A
matching child preserves its exit code or terminating Unix signal. `login` and
Google Cloud are still planned work. The `exec` preflight
uses normal AWS CLI credential
resolution, which may update AWS-owned caches under its documented behavior;
authmux does not request login or capture the resulting Credential.

Child processes inherit only `PATH`, `HOME`, `LANG`, `LC_ALL`, and `TERM`, plus
the selected provider profile. Credential environment variables and unrelated
parent state are removed. Immediately before spawn, authmux re-reads the
Project Binding and user configuration; a changed context fails closed and
must be retried.

The default suite never contacts AWS. An explicit live gate exercises
`doctor`, `status`, and guarded no-op execution against an existing context:

```console
AUTHMUX_LIVE_AWS_CONTEXT=crm \
AUTHMUX_LIVE_AWS_ACKNOWLEDGE_CACHE_WRITES=1 \
cargo test --test live_aws -- --ignored --exact \
  configured_aws_context_completes_the_live_cli_workflow
```

This gate may cause the AWS CLI to refresh provider-owned caches during the STS
preflight. Captured provider output is not printed by the test.

The user configuration remains at
`$XDG_CONFIG_HOME/authmux/config.toml` or `~/.config/authmux/config.toml`. The
optional root binding contains only:

```toml
version = 1

[project]
context = "crm"
```

`.authmux.toml` is ignored by this repository's default because project and
organization names can be sensitive. A project that intentionally shares the
binding must make that decision explicitly.

## Current state

The crate now contains the first test-driven AWS identity guard, bounded
provider probe runner, strict user and project config parsers, and isolated
child runner with exit/signal parity. It remains a development tracer rather
than a released CLI. CI runs the same format, strict lint, test, and locked
build gates on pinned Ubuntu and macOS runners.

Start here:

- [workplan.md](workplan.md) — scope, milestones, acceptance criteria, and risk controls
- [CONTEXT.md](CONTEXT.md) — canonical product language
- [AGENTS.md](AGENTS.md) — repository operating contract
- [ADR 0001](docs/adr/0001-delegate-credential-custody.md) — credential-custody decision
- [ADR 0002](docs/adr/0002-separate-status-from-execution-preflight.md) — read-only status boundary
- [Phase 0 evidence](docs/research/2026-08-03-phase-0-evidence.md) — dated competitor and provider findings
- [Build-versus-adopt benchmark](docs/research/2026-08-03-build-vs-adopt-benchmark.md) — pinned Atmos and direnv controls
- [Provider evidence matrix](docs/research/2026-08-03-provider-evidence-matrix.md) — command, selector, side-effect, and sensitivity decisions
- [GCP Phase 2 contract](docs/research/2026-08-03-gcp-phase-2-contract.md) — separate gcloud/ADC planes and mandatory no-write gate
- [Live AWS gate](docs/research/2026-08-03-live-aws-gate.md) — identifier-free evidence for the opt-in real-provider workflow

## License

MIT. See [LICENSE](LICENSE).

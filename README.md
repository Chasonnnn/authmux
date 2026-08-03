# authmux

`authmux` is an early local-first CLI for verifying and selecting authentication
contexts across developer tools without becoming a credential vault itself.

The repository is private during design and early validation. The code and
documentation are licensed under the MIT License so the project can be opened
when its security model and provider behavior are ready for public scrutiny.

## Current tracer

```console
authmux exec crm -- aws s3 ls
```

The implemented AWS-first tracer reads a user-owned context, observes the
selected account through the native AWS CLI, refuses an Expected Identity
mismatch, and otherwise creates a process-scoped environment for one child
command. `status`, `doctor`, `login`, repository binding, and Google Cloud are
still planned work. The `exec` preflight uses normal AWS CLI credential
resolution, which may update AWS-owned caches under its documented behavior;
authmux does not request login or capture the resulting Credential.

## Current state

The crate now contains the first test-driven AWS identity guard, bounded provider
probe runner, strict user-config parser, and isolated child runner. It remains a
development tracer rather than a released CLI.

Start here:

- [workplan.md](workplan.md) — scope, milestones, acceptance criteria, and risk controls
- [CONTEXT.md](CONTEXT.md) — canonical product language
- [AGENTS.md](AGENTS.md) — repository operating contract
- [ADR 0001](docs/adr/0001-delegate-credential-custody.md) — credential-custody decision
- [Phase 0 evidence](docs/research/2026-08-03-phase-0-evidence.md) — dated competitor and provider findings

## License

MIT. See [LICENSE](LICENSE).

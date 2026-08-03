# authmux

`authmux` is a planned local-first CLI for understanding, refreshing, and
selecting authentication contexts across developer tools without becoming a
credential vault itself.

The repository is private during design and early validation. The code and
documentation are licensed under the MIT License so the project can be opened
when its security model and provider behavior are ready for public scrutiny.

## Intended experience

```console
authmux status
authmux doctor
authmux login work-aws
authmux exec research-gcp -- gcloud storage ls
authmux exec crm-github -- gh repo view
```

Native tools retain credential custody: AWS tooling, `gcloud`, `gh`, SSH
agents, and similar systems continue to store and refresh their own sessions.
`authmux` reads safe status signals, invokes native login flows, and creates a
process-scoped environment for the selected project context.

## Current state

This initial commit establishes the product definition, terminology,
architecture decision, engineering rules, and phased execution plan. No
credential-handling implementation exists yet.

Start here:

- [workplan.md](workplan.md) — scope, milestones, acceptance criteria, and risk controls
- [CONTEXT.md](CONTEXT.md) — canonical product language
- [AGENTS.md](AGENTS.md) — repository operating contract
- [ADR 0001](docs/adr/0001-delegate-credential-custody.md) — credential-custody decision

## License

MIT. See [LICENSE](LICENSE).

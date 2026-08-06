# ADR 0010: Isolate GitHub CLI with native configuration directories

- Status: Accepted
- Date: 2026-08-05

## Context

GitHub CLI can store multiple accounts and switch the active account for a
host, but `gh auth switch` mutates shared configuration. That is unsafe for
parallel project and agent workflows. GitHub CLI also accepts `GH_TOKEN` and
`GITHUB_TOKEN`, which override stored credentials and could silently defeat a
configured Authentication Context.

GitHub CLI documents `GH_CONFIG_DIR` as the supported selector for its native
configuration directory. Its browser login normally stores the OAuth
Credential in the system credential store, but it can fall back to plaintext
storage when the credential store is unavailable. `gh auth status` validates
the active account and exposes token storage provenance without displaying the
Credential unless `--show-token` is explicitly requested.

Primary evidence:

- [GitHub CLI environment variables](https://cli.github.com/manual/gh_help_environment)
- [GitHub CLI authentication status](https://cli.github.com/manual/gh_auth_status)
- [GitHub CLI browser login](https://cli.github.com/manual/gh_auth_login)

## Decision

A GitHub Provider Profile contains only a user-owned `config_dir`, `hostname`,
and Expected Identity (`expected_login`). Authmux never reads `hosts.yml`, asks
GitHub CLI for a token, runs `gh auth switch`, or accepts a token field in its
configuration.

`authmux status --context NAME --provider github` runs this bounded native
probe with the selected `GH_CONFIG_DIR`:

```console
gh auth status --active --hostname HOST --json hosts
```

The command never includes `--show-token`. Authmux parses only the selected
host's active login, state, and token-source label. A usable observation
requires provider-reported success, an unambiguous active login, Expected
Identity equality, and `keyring` storage. Plaintext native storage, malformed
or truncated output, ambiguity, and provider failure fail closed with a
sanitized diagnostic.

`authmux login NAME --provider github` delegates to:

```console
gh auth login --hostname HOST --web --skip-ssh-key
```

The terminal and browser flow remain native. Authmux filters ambient GitHub
token variables, re-resolves the Authentication Context before mutation, and
performs the bounded status validation after native success. It does not
request an SSH key upload or claim success from the native exit code alone.

Guarded GitHub execution accepts only the `gh` CLI, validates the active login,
re-resolves the Authentication Context, and then launches the literal child
argument vector with `GH_CONFIG_DIR`, `GH_HOST`, disabled prompting, disabled
update notices, and disabled GitHub CLI telemetry. Ambient `GH_TOKEN`,
`GITHUB_TOKEN`, and enterprise token variables are not inherited. Raw Git is
rejected because `GH_CONFIG_DIR` does not select an SSH key or Git credential
helper.

`authmux status --all` observes every configured Provider Profile without a
Project Binding. Its JSON form is intended for agent preflights. A failed
provider produces a nonzero aggregate exit without discarding successful
observations.

## Consequences

GitHub remains the Credential custodian and authmux gains process-scoped
identity selection without global account switching. Separate identities on
the same host require separate user-owned GitHub configuration directories.

GitHub status contacts the provider and can take longer than AWS, GCP, or SSH
local observations. Systems where GitHub CLI falls back to plaintext token
storage are rejected until a supported system credential store is available.
This deliberately trades compatibility for a stronger custody boundary.

GitHub-only `gh` execution is supported in this slice. Raw Git authentication
and mixed-provider Execution Scopes remain fail-closed until each receives its
own tested selector contract.

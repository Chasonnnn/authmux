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

Secure-storage diagnostics distinguish evidence from access restrictions.
GitHub CLI 2.96.0 can retain a configuration-file source label after a failed
keyring lookup. A source label alone therefore does not prove plaintext storage.
Only a successful observation naming the selected configuration's `hosts.yml`
is reported as plaintext storage. Other non-keyring sources remain unverified.
Neither diagnostic includes the source label or configuration path.
Both cases block execution. A native probe failure alone does not recommend login.

Primary source contracts:

- [GitHub CLI 2.96.0 active-token selection](https://github.com/cli/cli/blob/v2.96.0/internal/config/config.go#L219-L241)
- [GitHub CLI 2.96.0 status source labels](https://github.com/cli/cli/blob/v2.96.0/pkg/cmd/auth/status/status.go#L337-L343)

When execution permissions restrict credential-store access, agents request
scoped access for the preserved guarded command and retry it once. An unchanged
failure stops the operation. This does not relax secure storage, change identity,
inspect credential files, or authorize a bare-provider fallback.

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

A child whose executable basename is `gh` requires a GitHub Provider Profile
before any provider observation. A cloud-only context returns a usage error
with an explicit GitHub-context selection action; it must not run AWS STS,
apply GCP selectors, or request cloud Reauthentication. This applies to both
repository bindings and explicit `--context` selection. Authmux does not infer
or switch to another context. Agents may explicitly select the one configured
GitHub-only context for the target host when no conflicting GitHub identity is
required, including inside a cloud-bound repository.

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

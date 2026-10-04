---
status: accepted
---

# Provider login shortcuts with repo context mappings

## Decision

`authmux aws`, `authmux gh`, `authmux gcloud`, and `authmux empireai` invoke the
existing AWS, GitHub, GCP, and SSH login handlers. Each accepts only
`--context NAME` and `--print-command`. They are explicit login operations and
do not forward arbitrary provider commands.

Version 1 project configuration retains the required `project.context` and
adds an optional `project.providers` table. Keys are the canonical provider
names `aws`, `github`, `gcp`, and `ssh`. Values name existing user-owned
Authentication Contexts. A cloud project can reference shared GitHub and SSH
contexts without repeating Provider Profiles or Expected Identities.

Shortcut selection follows this precedence:

1. Explicit `--context NAME`, including outside a repository.
2. The selected provider's repository mapping.
3. `project.context` when that provider has no mapping.

An invalid mapping, undefined context, or missing provider fails before native
login. Authmux never searches other contexts or substitutes ambient identity.
Mapping names and values pass the existing sanitized configuration boundary;
unknown providers, secret-shaped values, terminal controls, and provider
overrides are rejected. Repository discovery stays at the nearest Git root.

Every executing login re-resolves its selection after preview and before
native startup. AWS does this after its second bounded login-plan probe so a
mapping changed during either planning pass cannot redirect the login.
Provider selectors, native terminal handling, cancellation, exit codes, and
post-login evidence retain their existing contracts.

`context show` lists declared login mappings without provider contact. The
explicit `login CONTEXT --provider PROVIDER` form and the `exec-event-v1`
handoff remain unchanged. Captured agents use `--print-command`; the user
runs the executing shortcut in an external terminal.

## Scope and migration

The mappings apply to login shortcuts. `exec`, `status`, and `doctor` retain
their existing default context selection. Agents select a separately mapped
context explicitly for those commands. This avoids changing execution
identity as a side effect of adding login conveniences. Mixed-provider
execution remains unsupported.

Existing version 1 files need no migration. Upgrade the binary before adding
`project.providers`; older binaries reject unknown fields. No compatibility
fallback, credential migration, global identity switch, or new provider is
introduced. `empireai` uses a configured SSH host alias and does not imply a
fixed Empire AI endpoint.

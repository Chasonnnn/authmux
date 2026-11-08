# ADR 0014: Remove GitHub from authmux

- Status: Accepted
- Date: 2026-11-08
- Supersedes: ADR 0010 and the GitHub portions of ADRs 0012 and 0013

## Context

The primary workflow uses one GitHub identity. GitHub context selection adds
provider probes, credential-store failures, and maintenance without useful
identity separation for that workflow.

## Decision

Remove the GitHub Provider Adapter, configuration, selectors, status, doctor,
login, execution, and `gh` shortcut. Run GitHub CLI directly with its native
authentication. Authmux continues to manage AWS, Google Cloud, and SSH.

Reject old GitHub user profiles and project mappings through strict,
sanitized configuration validation. Reject wrapped `gh` commands before
configuration loading or cloud probes, including executable paths ending in
`gh`. Do not reinterpret them as cloud operations or silently forward them.

Keep secret-shaped GitHub token detection and ambient-secret filtering.
These protect supported providers regardless of which provider issued a secret.
Preserve aggregate status and partial-failure behavior with supported fixtures.

## Consequences

Existing GitHub configurations and wrapped commands require the documented
[migration](../migrations/remove-github-provider.md). Authmux no longer checks
GitHub identity or credential storage. Native GitHub authentication remains
under the user's control. No credential or provider-owned file is migrated.

Existing status and context-list output shapes remain unchanged. The
`exec-event-v1` provider set narrows to AWS; its remaining event shape is unchanged.
Historical research records remain evidence of the retired implementation.

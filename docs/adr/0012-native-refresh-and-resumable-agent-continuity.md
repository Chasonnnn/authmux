---
status: accepted
---

# Use native refresh and resumable agent continuity

## Context

Long agent tasks commonly authenticate, test, repair code, and later return to
deployment or log inspection after a provider Session has ended. Repeating the
whole task loses useful state; periodically launching login does not solve the
problem because human SSO, browser, and MFA Sessions have provider-controlled
maximum lifetimes.

AWS and Google tooling can renew provider-owned Credentials during an explicit
operation while their parent Session remains usable. GitHub Reauthentication is
interactive, and OpenSSH keepalives preserve a transport rather than renew a
Provider Identity. A universal refresh timer would therefore create provider
traffic and a long-lived credential-rich process without guaranteeing
continuity.

## Decision

Authmux leaves automatic Credential renewal with the native provider during
explicitly requested guarded execution. It adds no background daemon, scheduled login,
Credential cache parser, or implicit interactive flow.

When a pre-execution Provider Adapter can narrowly classify an expired or
missing Session, `authmux exec` does not start the requested child. It exits
`10` and writes one `exec-event-v1` JSON object to stderr with:

- `event: reauthentication_required`;
- the resolved Authentication Context and provider;
- a literal login argument vector ending in `--print-command`;
- `retry: original_command_once`.

Captured agents validate the event, preserve the original argument vector, run
the non-executing login preview once, and pause. The user reruns that login
without `--print-command` in an external terminal. After confirmation, the
agent retries the original guarded operation exactly once. A repeated event or
malformed event stops without another login, identity switch, or fallback.

AWS recognizes a bounded set of expired and missing-session signatures from
the capped STS preflight. Unknown, malformed, unreachable, or sensitive output
remains a sanitized provider failure. A bounded AWS endpoint-connection
signature requests network access and retry without suggesting
Reauthentication. GitHub uses its typed unusable-Session result. GCP remains
child-owned: authmux does not capture arbitrary child output or add a
resource-specific probe merely to classify Reauthentication. SSH retains its
explicit reusable-transport contract.

Work expected to outlive a human Session uses repository-approved OIDC or
workload identity for deployment and sanitized log retrieval. Authmux may guard
the command that triggers or observes that workflow, but it does not create
static cloud keys or launch an entire coding agent inside an Execution Scope.

## Consequences

An authentication interruption pauses one operation rather than discarding the
agent's task state. Native Credential renewal remains automatic where the
provider already supports it, while browser and MFA exchanges stay user-controlled.

Exit code `10` and `exec-event-v1` become compatibility contracts. Provider
classification stays intentionally incomplete; false generic failures are
safer than false Reauthentication claims. Fully unattended continuity requires
workload identity and cannot be promised for a human Session.

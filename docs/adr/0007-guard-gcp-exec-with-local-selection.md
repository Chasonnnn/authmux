# ADR 0007: Guard Google Cloud execution with local selection

- Status: Accepted
- Date: 2026-08-03

## Context

ADR 0006 separates the gcloud CLI and Application Default Credentials (ADC)
planes and prohibits `status` and `doctor` from running gcloud. Protected local
metadata can verify the selected gcloud identity and optional project, but it
cannot prove that credentials are present, refreshable, or authorized for a
resource. The ADC plane exposes even less safe local evidence: authmux can
validate the declared credential-file path without opening the file, but it
cannot verify the credential identity or usability.

An execution preflight that prints an access token, opens native credential
stores, or calls an arbitrary Google Cloud resource would exceed authmux's
credential-custody boundary. Unlike AWS STS `GetCallerIdentity`, Google Cloud
does not expose one provider-neutral identity operation that safely validates
both gcloud and every ADC credential mode.

## Decision

Guard GCP execution according to the credential plane the child will use:

- a child whose executable basename is exactly `gcloud` requires a declared
  gcloud CLI plane whose protected local metadata matches the Expected
  Identity, optional Expected Source Identity, and optional expected project;
- every other child requires a declared ADC credential-file plane whose
  protected path metadata is available;
- ambient ADC, well-known ADC, metadata-server fallback, and undeclared
  provider selection remain unsupported;
- a context containing GCP plus any other provider fails before observation or
  child execution until provider guards can be composed without silently
  weakening either provider's policy.

The selected Authentication Context is re-read immediately before spawn. A
change to the Project Binding, GCP Provider Profile, Expected Identity, or
credential-plane composition fails closed.

authmux passes only the documented selectors from the user-owned configuration
through the filtered child environment. It does not set an account, project,
impersonation target, token, or credential content. The child is spawned with
the exact argument vector and its native exit code or signal is preserved.

This is an execution-selection guard, not live credential validation. A
successful guard means only that the requested local selection matches the
declared context. Credential usability, refresh, authorization, and expiry
remain unverified until the child performs its own provider operation.

## Consequences

Explicit `authmux exec` may cause gcloud or a Google client library to refresh
or update its provider-owned caches. That behavior belongs to the child and is
permitted only because the user explicitly requested execution; read-only
`status` and `doctor` remain zero-provider and no-write by authmux.

The basename rule is deliberately narrow. Wrappers around gcloud use the ADC
path unless a later, explicit contract supports them. Children can override
process defaults with their own flags or environment handling, so authmux does
not claim that the selectors form an authorization sandbox.

Users without an explicit ADC plane can run guarded gcloud commands but cannot
run SDK, Terraform, or other non-gcloud children through a GCP context. This is
more restrictive than ambient ADC discovery and prevents an agent from
silently using an unrelated local, workload, or metadata-server identity.

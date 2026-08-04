# ADR 0006: Observe Google Cloud selection without running gcloud

- Status: Accepted
- Date: 2026-08-03

## Context

Google Cloud exposes two distinct credential planes: the gcloud CLI uses its
own credential store and named configurations, while Application Default
Credentials (ADC) uses an independent search order. A successful observation
of one plane cannot establish the identity or usability of the other.

The Phase 2 research contract required a disposable, network-denied purity
gate before any gcloud command could be used by read-only `status` or `doctor`.
The gate ran Google Cloud SDK 576.0.0 against a fictional configuration with
prompts, file logging, usage reporting, surveys, and update checks disabled.
The candidate local listing commands still created `credentials.db`,
`access_tokens.db`, `crm_configs.db`, `gce`, and survey metadata. The original
configuration file was unchanged and no provider API was contacted, but the
zero-write requirement failed.

Google documents that `CLOUDSDK_CONFIG` selects the gcloud configuration
directory and `CLOUDSDK_ACTIVE_CONFIG_NAME` selects one named configuration.
Google also documents that ADC checks `GOOGLE_APPLICATION_CREDENTIALS` before
the well-known local file and metadata server, and that ADC credentials are
distinct from gcloud CLI credentials.

Sources:

- [gcloud named configurations](https://docs.cloud.google.com/sdk/gcloud/reference/topic/configurations)
- [Application Default Credentials search order](https://docs.cloud.google.com/docs/authentication/application-default-credentials)
- [gcloud authentication list](https://docs.cloud.google.com/sdk/gcloud/reference/auth/list)

## Decision

Read-only GCP observation does not execute `gcloud`.

The gcloud CLI plane may inspect only the explicitly selected, protected named
configuration properties file. The parser is bounded and narrow: it retains
only `core/account`, optional `core/project`, and the presence of unsupported
credential or impersonation overrides. It never opens credential databases,
token caches, logs, survey files, or broad configuration exports. Native values
and paths are never included in failures.

The ADC plane is selection-only. authmux validates protected path metadata for
an explicitly declared credential file but never opens the file or infers an
identity from its path or filename.

Both planes remain independent Status Observations:

- gcloud configuration metadata may establish an Observed Identity and an
  Identity Match, but Session Usability remains `indeterminate`;
- ADC Identity Match remains `unverified` and Session Usability remains
  `indeterminate`;
- Reauthentication Need remains `unknown`, Evidence Level is
  `local_metadata`, and `provider_contacted` is false;
- neither plane reports or infers expiration.

`doctor` may inspect executable and path metadata but does not run `gcloud`.
Process-scoped execution may later set the documented selectors, but this ADR
does not authorize a live provider preflight, implicit login, ambient ADC
fallback, or global configuration activation.

## Consequences

Status can detect an unintended local gcloud account selection without
modifying provider-owned state, but it cannot say whether credentials exist,
can refresh, or authorize a resource request. ADC status can say only whether
the declared selector is structurally available to a child.

Doctor cannot report the installed gcloud version. This is deliberately weaker
than running `gcloud --version`, because even that command participated in the
failed disposable purity gate.

The implementation must protect file reads against symlinks, ownership drift,
permissive parent directories, oversized input, malformed metadata, and
time-of-check/time-of-use replacement. Any uncertainty fails closed without
falling back to a provider command.

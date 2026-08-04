# ADR 0008: Delegate GCP login to the selected gcloud configuration

- Status: Accepted
- Date: 2026-08-03

## Context

Guarded GCP execution can verify protected local gcloud identity and project
selection, but it intentionally cannot prove live credential usability before
spawning a child. When gcloud reports that reauthentication is required,
authmux needs an explicit recovery path without reading, copying, or brokering
Google credentials.

Google documents `gcloud auth login ACCOUNT --force` as a browser-based user
authorization flow that obtains a new credential even when a credential for
the account is already stored. The command activates that account in the
selected gcloud configuration. `--update-adc` is a separate option that writes
the well-known Application Default Credentials file.

Sources:

- [gcloud auth login](https://docs.cloud.google.com/sdk/gcloud/reference/auth/login)
- [gcloud named configurations](https://docs.cloud.google.com/sdk/gcloud/reference/topic/configurations)

## Decision

`authmux login CONTEXT --provider gcp` delegates gcloud CLI reauthentication to
the native command:

```console
gcloud auth login ACCOUNT --brief --force
```

The affected account is the declared Expected Source Identity for an
impersonated profile, otherwise the declared Expected Identity. A GCP context
without a gcloud CLI credential plane fails closed; authmux does not substitute
`gcloud auth application-default login` for an explicit ADC credential-file
plane.

Before spawning gcloud, authmux displays the Authentication Context, gcloud
configuration name, Expected Identity, affected login account, credential
plane, and literal native command. It then re-reads the user configuration and
rejects changes to the context name, GCP Provider Profile, or provider
composition.

The child receives the filtered environment plus only these login selectors:

```text
CLOUDSDK_CONFIG
CLOUDSDK_ACTIVE_CONFIG_NAME
CLOUDSDK_CORE_DISABLE_FILE_LOGGING=1
CLOUDSDK_CORE_DISABLE_USAGE_REPORTING=1
CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK=1
```

Interactive prompts remain enabled. authmux does not pass the ADC selector,
set project or account properties through environment variables, use
`--update-adc`, or activate another global named configuration. The selected
gcloud configuration and provider-owned credential store remain authoritative.

The terminal is attached directly. Browser URLs, authorization codes, native
stdout and stderr, and credential material bypass authmux capture and logging.
A zero exit proves only that the native login command completed successfully;
live Session Usability must be established by a separately authorized provider
operation.

## Consequences

Login is deliberately state-changing and can replace the stored user
credential and active account inside the selected gcloud configuration. The
`--force` flag makes the recovery behavior deterministic at the cost of always
requiring the native authorization flow.

ADC remains independent. A successful gcloud login does not create, replace,
or validate the credential file declared by the ADC plane. Users requiring ADC
reauthentication need a provider-supported workflow that writes the explicitly
declared file without authmux handling its contents; no such generic workflow
is added by this decision.

`status`, `doctor`, and `exec` never invoke login implicitly and retain their
existing evidence and no-write boundaries.

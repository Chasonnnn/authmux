# Google Cloud Phase 2 implementation contract

Date: 2026-08-03

## Evidence boundary

This contract uses current official Google Cloud documentation plus safe local
help and version output from Google Cloud SDK `576.0.0`. Research did not read a
credential database or ADC file, print a token, contact a Google Cloud resource
API, activate a configuration, or run a login flow.

Google documents named gcloud configurations and Application Default
Credentials as distinct authentication surfaces. `CLOUDSDK_CONFIG` selects the
gcloud configuration directory, while `CLOUDSDK_ACTIVE_CONFIG_NAME` selects one
named configuration. ADC uses an independent search order beginning with
`GOOGLE_APPLICATION_CREDENTIALS`, then a well-known local file, then an
attached service account.

## Decision

Implement two explicit credential planes:

1. **gcloud CLI plane**: a user-owned config directory, named configuration,
   Expected Identity, and optional expected project.
2. **ADC plane**: an explicit user-owned credential-file reference and declared
   Expected Identity.

The planes must produce independent observations. A successful gcloud CLI
observation never implies that ADC is selected, usable, or associated with the
same identity.

Initial ADC support is selection-only:

- authmux may validate path metadata without opening the file;
- it may set `GOOGLE_APPLICATION_CREDENTIALS` for a child;
- it always reports ADC Session Usability as `indeterminate` and Identity Match
  as `unverified`;
- it must not infer identity from a filename, path, or file existence.

Ambient, well-known-location, metadata-server, generated-user-ADC, and
executable-sourced federation modes remain unsupported. Arbitrary GCP child
execution requires an explicit ADC credential-file reference so client
libraries cannot silently fall through to an unrelated ambient identity.

## Proposed user-only configuration

```toml
[contexts.crm.providers.gcp.gcloud]
config_dir = "/absolute/user-owned/gcloud-config-root"
configuration = "crm"
expected_principal = "researcher@example.test"
expected_source_account = "researcher@example.test" # optional
expected_project = "fictional-project"              # optional

[contexts.crm.providers.gcp.adc]
mode = "credential_file"
credential_file = "/absolute/user-owned/credential-config.json"
expected_principal = "service-account@example.test"
```

Repository configuration continues to contain only the Authentication Context
name. It cannot define provider paths, modes, selectors, or identities.

Validation must reject:

- relative paths, `~`, NUL, inline JSON, PEM, token-shaped values, and unknown
  fields;
- paths outside user config or a path supplied for a different ADC mode;
- configuration names other than a lowercase letter followed by lowercase
  letters, digits, or hyphens;
- the reserved configuration name `NONE`;
- ambient, well-known, metadata, executable, and generated-user ADC modes;
- comma-separated impersonation chains in the initial implementation.

Errors and reports must not expose full provider paths.

## Process selectors

The gcloud CLI plane adds only:

```text
CLOUDSDK_CONFIG=<validated user-owned directory>
CLOUDSDK_ACTIVE_CONFIG_NAME=<validated configuration>
CLOUDSDK_CORE_DISABLE_PROMPTS=1
CLOUDSDK_CORE_DISABLE_FILE_LOGGING=1
CLOUDSDK_CORE_DISABLE_USAGE_REPORTING=1
CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK=1
```

The ADC plane adds only:

```text
GOOGLE_APPLICATION_CREDENTIALS=<validated user-owned credential-file reference>
```

The inherited environment must remove all other `CLOUDSDK_*`,
`GOOGLE_APPLICATION_CREDENTIALS`, `GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES`,
`GOOGLE_CLOUD_PROJECT`, `GCLOUD_PROJECT`, and token-shaped Google variables.
authmux must not set account, project, access-token-file, credential override,
or impersonation properties itself. `HOME` remains the normal child home.

The selection is a process default, not an authorization sandbox. A child that
explicitly supplies gcloud-wide `--account`, `--project`, `--configuration`, or
`--impersonate-service-account` flags can override defaults; authmux must state
this limitation rather than claiming enforcement.

## Local-only observation candidates

All candidates require the bounded runner, selector environment above,
`--quiet`, `--verbosity=error`, output caps, and sanitized typed failures.

Doctor candidates:

1. `gcloud --version`
2. `gcloud config configurations describe NAME --format=json --quiet
   --verbosity=error`
3. ADC path metadata checks for existence, regular-file type, and child
   readability without opening the file

Status candidates:

1. `gcloud config list core/account --configuration NAME
   --format=value(core.account) --quiet --verbosity=error`
2. the equivalent narrow query for `core/project`
3. narrow queries for `auth/access_token_file`,
   `auth/credential_file_override`, `auth/disable_credentials`, and
   `auth/impersonate_service_account`
4. only when unsupported overrides are absent, `gcloud auth list
   --configuration NAME --filter=status:ACTIVE --format=value(account) --quiet
   --verbosity=error`

A single active source account plus an optional single impersonated service
account can produce a local-metadata identity comparison. Multiple lines,
credential overrides, disabled credentials, or impersonation chains fail
closed as unsupported or malformed provider configuration. Local matches remain
`indeterminate` with `local_metadata` evidence and no inferred expiration.

## Prohibited operations

Status, doctor, and parsers must never use:

- `gcloud auth login`, `revoke`, `activate-service-account`, or `init`;
- token or identity-token printing commands;
- any `gcloud auth application-default` mutation or token-printing command;
- `gcloud config set` or `unset`, or configuration activate/create/delete/rename;
- a resource API call as a generic health check;
- `--log-http`, debug verbosity, token decoding, or tokeninfo calls;
- credential database, token cache, ADC file, or raw broad-config parsing;
- `CLOUDSDK_CONFIG` as an ADC selector.

## Mandatory implementation gate

Before merging a real gcloud Status Adapter, run the candidate commands against
a disposable fictional `CLOUDSDK_CONFIG` with network denied. Compare complete
before/after filesystem inventories and verify:

- no auth or configuration state changed;
- prompts, file logging, usage reporting, and update checks stayed disabled;
- named selection did not change the globally active configuration;
- default tests required no real credential database or ADC file.

Official documentation describes these commands as local listing operations,
but does not guarantee perpetual zero-write or zero-network behavior. Failure of
this synthetic purity gate blocks the adapter; it must not be explained away as
read-only.

## Primary sources

- [Managing gcloud CLI configurations](https://docs.cloud.google.com/sdk/docs/configurations)
- [Application Default Credentials search order](https://docs.cloud.google.com/docs/authentication/application-default-credentials)
- [gcloud auth list](https://docs.cloud.google.com/sdk/gcloud/reference/auth/list)
- [gcloud config list](https://docs.cloud.google.com/sdk/gcloud/reference/config/list)
- [gcloud configuration creation and names](https://docs.cloud.google.com/sdk/gcloud/reference/config/configurations/create)
- [Workload Identity Federation executable sources](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-other-providers)

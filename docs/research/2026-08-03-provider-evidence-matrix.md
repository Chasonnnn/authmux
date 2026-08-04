# Provider evidence matrix

Date: 2026-08-03

## Evidence boundary

This matrix combines official provider documentation with help and version
output from locally installed CLIs. Local inspection ran with empty temporary
home, XDG, AWS, gcloud, and GitHub CLI configuration directories. It did not
invoke a provider status or login command, inspect a real credential store,
successfully contact a provider API, or print a Credential. The execution
environment denied general network access.

The isolated version commands still created gcloud metrics/survey/log files and
a GitHub CLI device identifier inside the disposable directories. Those files
were inventoried by path and removed without reading their contents. Production
probes must disable telemetry and update checks where supported, but must not
pretend that a third-party CLI is filesystem-pure merely because the requested
operation is read-only.

Installed versions:

| CLI | Version |
|---|---:|
| AWS CLI | 2.36.11 |
| Google Cloud SDK | 576.0.0 |
| GitHub CLI | 2.96.0 |
| OpenSSH | 10.2p1 |

## Command decisions

| Provider plane | Candidate command | Evidence | Side effects and uncertainty | Output sensitivity | Bound | Decision |
|---|---|---|---|---|---:|---|
| AWS CLI installation | `aws --version` | local executable and semantic version | Loads the installed CLI only; does not inspect a Session or contact AWS | runtime, platform, and architecture metadata are discarded after narrow version parsing | 2 s / 4 KiB | doctor-only local check; require AWS CLI v2 |
| AWS local profile | `aws configure get sso_account_id --profile NAME` | configured account metadata | Reads native config; does not establish Session usability and is absent for many profile types | account ID | 2 s / 4 KiB | possible read-only status evidence, never provider validation |
| AWS login local profile | `aws configure get login_session --profile NAME` | account embedded in configured login ARN | Reads native config, not the login cache; does not establish Session usability | full principal ARN is parsed narrowly, only its account is retained, and its resource is discarded | 2 s / 4 KiB | fallback local-metadata evidence when `sso_account_id` is absent; never provider validation |
| AWS live identity | `aws sts get-caller-identity --query Account --output text --no-cli-pager --no-cli-auto-prompt` | provider-validated account | May retrieve, assume, or automatically refresh temporary credentials and update AWS-owned caches | account ID; native stderr may contain sensitive metadata | 5 s / 4 KiB | allowed for guarded `exec` preflight; prohibited for read-only `status` |
| AWS IAM Identity Center login | `aws sso login --profile NAME` | explicit Reauthentication | Opens an authorization flow and writes provider-owned cache state | authorization URLs and organization metadata | interactive | explicit `login` only |
| AWS console credential login | `aws login --profile NAME` | explicit Reauthentication for a login profile | Opens an authorization flow and writes provider-owned login cache state | authorization URLs and principal metadata | interactive | explicit `login` only; available in AWS CLI 2.32.0 and later |
| gcloud CLI local identity | `gcloud auth list --filter=status:ACTIVE --format=value(account) --configuration NAME` | locally active credentialed account | Reads the selected gcloud configuration; does not prove token usability or authorization | account identifier | 3 s / 8 KiB | Phase 2 local-metadata candidate |
| gcloud CLI live validation | no generic safe `whoami` command selected | none | Service calls can refresh access credentials and require project-specific authorization | provider errors can include project and account metadata | n/a | unresolved; do not claim live CLI status |
| Google ADC | no command selected | none | ADC uses a separate search order and client libraries may refresh credentials; success in gcloud CLI says nothing about ADC | credential-file paths and principals can be sensitive | n/a | independent Phase 2 evidence surface |
| GitHub CLI | `gh auth status --active --hostname HOST` with isolated `GH_CONFIG_DIR` | tested account authentication state | Reads the selected config and OS credential store, and contacts GitHub; update checks and telemetry must be disabled | hostname, username, scopes, storage location; never add `--show-token` | 5 s / 16 KiB | evidence-only until keyring fallback and Git helper isolation are proven |
| GitHub active account mutation | `gh auth switch --hostname HOST --user USER` | none | Mutates active-account configuration | identity metadata | n/a | prohibited during status and exec |
| OpenSSH installation | `ssh -V` | local executable and narrowly parsed version | Displays the client version and exits without a destination or remote connection | runtime library metadata is discarded after version parsing | 2 s / 4 KiB | implemented local-readiness check; no Session or identity claim |
| SSH agent | `ssh-add -l -E sha256` with selected `SSH_AUTH_SOCK` | local key fingerprints | Reads agent state only; does not prove remote identity, authorization, MFA, or expiry | fingerprints and comments are sensitive metadata | 2 s / 16 KiB | local-readiness evidence only |
| SSH configuration | `ssh -G -F FILE HOST` | effective local client configuration | Expands configuration without connecting, but evaluates `Match` blocks and `Match exec` can execute a command under the user's shell | usernames, hosts, paths, proxy commands | 2 s / 32 KiB | rejected for automated status and doctor |
| Institutional SSH/MFA | no generic login or status command | none | Interactive remote authentication has no portable, inspectable future expiry | institution and username metadata | n/a | defer remote probe and expiry claims |

## Process-scoped selectors

| Provider | Safe selector candidates | Precedence or mutation risk |
|---|---|---|
| AWS | `AWS_PROFILE`, optionally user-owned `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` | inherited `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, credential-process variables, and web-identity variables can override or bypass the intended profile and must not be inherited |
| gcloud CLI | `CLOUDSDK_ACTIVE_CONFIG_NAME` or `--configuration`; isolated `CLOUDSDK_CONFIG` only when the directory already belongs to the user | `gcloud config configurations activate` mutates global active configuration and is prohibited |
| Google ADC | `GOOGLE_APPLICATION_CREDENTIALS` references a user-owned credential file but is not a named-profile selector | ADC search order includes environment, local well-known files, and metadata service; no portable context mapping is proven |
| GitHub CLI | pre-provisioned, user-owned `GH_CONFIG_DIR`; explicit hostname | token environment variables override stored credentials and must be removed; `gh auth switch` mutates the directory |
| SSH | `SSH_AUTH_SOCK` or `IdentityAgent`, paired with user-owned configuration and `IdentitiesOnly yes` | agent selection alone does not constrain identity files or prove the remote principal |

Repository configuration must not introduce any selector name, executable,
path, or command. User configuration may eventually reference user-owned
provider configuration paths, but the current AWS tracer supports only a
profile name.

## Failure fixture taxonomy

Every supported Adapter contract needs fictional, redacted fixtures for:

| Case | Observable input | Required normalized behavior |
|---|---|---|
| success | exact narrow identity output, exit 0 | usable only when the command is documented as provider validation |
| expired | known provider error category | unusable, `expired`, Reauthentication required; never infer an expiry timestamp |
| missing login | known no-session category | unusable, `missing`, Reauthentication required |
| missing executable | spawn `NotFound` | typed provider/tool failure with install action |
| timeout | deadline exceeded | indeterminate, `unreachable`, Reauthentication unknown |
| malformed output | exit 0 with invalid or extra identity data | indeterminate, `provider_error`; do not guess |
| unreachable service | known connectivity category | indeterminate, `unreachable`; preserve other providers' observations |
| sensitive stderr | token-like and path-like seeded bytes | no seeded value reaches errors, reports, snapshots, or logs |

The current AWS `exec` Adapter has checked-in fictional fixtures for success,
expired, missing-login, unreachable, malformed, and sensitive output, plus
runner coverage for a missing executable, timeout, and output caps. It still
collapses expired, missing-login, and unreachable provider output into one
sanitized execution failure. A read-only `status` command therefore requires a
separate local-metadata observation contract and an optional Observed Identity
before it can be implemented honestly.

## Prohibited commands and interpretations

- AWS credential export commands and raw cache inspection.
- `gcloud auth print-access-token`, `gcloud auth
  application-default print-access-token`, and ADC file parsing.
- `gh auth token`, `gh auth status --show-token`, copied `hosts.yml` files, or
  token environment variables.
- `ssh-add -L` output in reports, remote password/MFA probes, or generated
  `GIT_SSH_COMMAND` values.
- Exact expiration unless a provider reports it directly with provenance.
- Treating configured or locally active metadata as proof of Session usability.

## Implementation consequence

`context show` and `context list` explain user configuration without touching
provider state. AWS `status` uses only local profile metadata and reports
Session Usability as `indeterminate`. `doctor` adds a narrowly parsed local AWS
CLI version check. Live `get-caller-identity` remains an `exec` preflight unless
a no-write provider mechanism is proven. ADR 0002 records this separation.

## Primary sources

- [AWS caller identity](https://docs.aws.amazon.com/cli/latest/reference/sts/get-caller-identity.html)
- [AWS IAM Identity Center configuration and refresh](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)
- [AWS console credential login](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sign-in.html)
- [AWS configuration and credential files](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)
- [gcloud auth list](https://docs.cloud.google.com/sdk/gcloud/reference/auth/list)
- [Google Application Default Credentials search order](https://docs.cloud.google.com/docs/authentication/application-default-credentials)
- [GitHub CLI authentication status](https://cli.github.com/manual/gh_auth_status)
- [GitHub CLI environment variables](https://cli.github.com/manual/gh_help_environment)
- [GitHub CLI account switching](https://cli.github.com/manual/gh_auth_switch)
- [OpenSSH `ssh-add`](https://man.openbsd.org/ssh-add.1)
- [OpenSSH client](https://man.openbsd.org/ssh)
- [OpenSSH client configuration](https://man.openbsd.org/ssh_config)

# Phase 0 landscape and provider evidence

Date: 2026-08-03

This evidence snapshot records supported public behavior, locally installed
CLI versions, and isolated fictional trials without inspecting real identities,
credential caches, or tokens. Provider behavior must still be confirmed with
redacted contract fixtures before an Adapter is described as supported.

## Local tool surface

| Tool | Observed version | 0.1 disposition |
|---|---:|---|
| AWS CLI | 2.36.11 | AWS-first implementation target |
| gcloud CLI | 576.0.0 | Phase 2; CLI and ADC handled separately |
| GitHub CLI | 2.96.0 | evidence-only isolation spike |
| OpenSSH | 10.2p1 | local-readiness evidence only |

## Build-versus-adopt evidence

- [Atmos](https://github.com/cloudposse/atmos) is the closest current
  competitor. Its OSS authentication surface includes login, identity,
  execution, shell, environment, listing, logout, and validation across cloud
  workflows. It is primarily an infrastructure runtime and may materialize or
  manage credentials. The authmux hypothesis remains narrower: native provider
  custody, read-only observation, user-owned contexts, restricted repository
  bindings, and fail-closed Expected Identity comparison.
- [Granted](https://github.com/fwdcloudsec/granted) is an actively maintained
  AWS-focused profile, IAM Identity Center, role-assumption, and browser-console
  tool. Native AWS profiles remain the 0.1 target; no first-class Granted
  Adapter is justified yet.
- [Leapp](https://github.com/Noovolari/leapp) is an Electron desktop application
  for AWS and Azure session management with a CLI that depends on the running
  app. Its daemon, storage, and rotation model is outside the authmux boundary.
- [direnv](https://github.com/direnv/direnv) is a useful dogfood control for
  directory-scoped environment selection, but authorized `.envrc` files execute
  repository-local shell code and provide no identity or Session observation.
- Upstream [99designs/aws-vault](https://github.com/99designs/aws-vault) declares
  itself abandoned. It is prior art, not a 0.1 integration candidate.

Before authmux expands beyond the AWS tracer, run the same fictional mismatch
workflow in Atmos and with `direnv` plus native CLIs, using Granted for AWS
where it is already configured. Continue only if the identity guard or
trust/custody model is materially safer or simpler.

The versioned comparison is complete in
[`2026-08-03-build-vs-adopt-benchmark.md`](./2026-08-03-build-vs-adopt-benchmark.md).
It supports continuing only the narrow native-custody identity guard. Granted
was not installed or configured, so it was correctly omitted from the control.

The command, selector, side-effect, sensitivity, timeout, and failure-fixture
decisions are consolidated in
[`2026-08-03-provider-evidence-matrix.md`](./2026-08-03-provider-evidence-matrix.md).

## Provider feasibility

### AWS

`AWS_PROFILE`, `AWS_CONFIG_FILE`, and `AWS_SHARED_CREDENTIALS_FILE` are native
process selectors. Inherited credential variables must be removed because they
can override profile selection. `aws sts get-caller-identity` provides a safe
remote account/ARN observation but no exact expiration. Modern IAM Identity
Center sessions can renew role credentials while their SSO session remains
valid, and AWS documents that only one login can be active for a named SSO
session. Normal AWS credential resolution may therefore update AWS-owned caches;
the current tracer permits that only during explicit `exec` preflight and does
not yet claim the stricter `status` contract. Phase 0 must record those side
effects and test concurrent profiles that share a session.

Sources: [AWS environment variables](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html),
[caller identity](https://docs.aws.amazon.com/cli/latest/reference/sts/get-caller-identity.html),
[IAM Identity Center configuration](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html),
[SSO login](https://docs.aws.amazon.com/cli/latest/reference/sso/login.html).

### Google Cloud

Named gcloud configurations can be selected with
`CLOUDSDK_ACTIVE_CONFIG_NAME`, but gcloud CLI credentials and Application
Default Credentials are distinct. ADC has a search order rather than a native
named-profile selector. Every declared credential plane requires its own
Expected Identity and Status Observation; success in one must not imply success
in the other.

Sources: [gcloud configurations](https://docs.cloud.google.com/sdk/docs/configurations),
[authentication overview](https://docs.cloud.google.com/docs/authentication),
[ADC search order](https://docs.cloud.google.com/docs/authentication/application-default-credentials).

### GitHub

`GH_CONFIG_DIR` can isolate GitHub CLI configuration, but multi-account
selection otherwise mutates active-user metadata. The only acceptable Phase 0
hypothesis is a pre-existing, user-owned directory per context while the OS
keyring remains credential custodian. authmux must not extract `GH_TOKEN`, copy
`hosts.yml`, call `gh auth switch` on a shared directory, or run global Git
credential-helper setup. Secure-storage fallback and plain Git behavior remain
unproven.

Sources: [GitHub CLI environment](https://cli.github.com/manual/gh_help_environment),
[login storage behavior](https://cli.github.com/manual/gh_auth_login),
[authentication status](https://cli.github.com/manual/gh_auth_status).

### SSH and institutional MFA

`ssh -V` is the selected local-readiness probe. It exits after displaying the
client version, so authmux can verify the installed OpenSSH client without a
destination, provider contact, agent inspection, or SSH configuration
evaluation. The implementation retains only a narrowly parsed version.

`IdentityAgent` or `SSH_AUTH_SOCK` can select an agent, while `IdentitiesOnly`
limits offered identities when paired with user-owned SSH configuration.
Agent inspection reveals local readiness only; it cannot prove remote identity,
authorization, MFA state, or future expiry. Remote probes are therefore
deferred. `GIT_SSH_COMMAND` is shell-interpreted by Git and conflicts with the
argv-only invariant.

`ssh -G` is excluded from automated status and doctor checks. Although it does
not connect, it evaluates `Host` and `Match` blocks; OpenSSH documents that
`Match exec` runs a command under the user's shell. Its expanded output also
contains sensitive client metadata.

Sources: [OpenSSH client](https://man.openbsd.org/ssh),
[OpenSSH client configuration](https://man.openbsd.org/ssh_config),
[Git environment variables](https://git-scm.com/docs/git),
[Empire AI SSH guidance](https://docs.ccr.buffalo.edu/en/latest/howto/empireai/).

## Prohibited evidence paths

The evidence collector must not use commands that print or export Credentials,
including AWS credential export, gcloud access-token printing, or GitHub token
printing. It must not parse raw credential caches, decode tokens, generate
`GIT_SSH_COMMAND`, infer an expiration time, or treat local metadata as remote
authorization proof.

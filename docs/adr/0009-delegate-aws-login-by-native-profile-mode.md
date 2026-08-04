# ADR 0009: Delegate AWS login by native profile mode

- Status: Accepted
- Date: 2026-08-04

## Context

AWS CLI v2 supports two explicit browser-based reauthentication commands with
different profile contracts. IAM Identity Center profiles use
`aws sso login --profile NAME`. Console-login profiles introduced in AWS CLI
2.32.0 use `aws login --profile NAME` and declare a `login_session`. A selected
role profile may not own either login mechanism; its `source_profile` owns the
reauthentication state used before the role is assumed.

Choosing one command for every AWS Provider Profile would either fail on valid
profiles or risk starting configuration for the wrong profile. Reading native
credential or token caches would violate authmux's credential-custody boundary.

Primary evidence:

- [AWS console credential login](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sign-in.html)
- [AWS IAM Identity Center login](https://docs.aws.amazon.com/cli/latest/reference/sso/login.html)
- [AWS configuration settings](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)

## Decision

`authmux login CONTEXT --provider aws` delegates explicit Reauthentication to
the supported native command selected from documented local profile metadata.
Before previewing a mutation, the AWS login Adapter performs bounded, capped
`aws configure get SETTING --profile NAME` probes. It inspects only
`login_session`, `sso_account_id`, `role_arn`, and `source_profile`; it never
opens AWS configuration or credential-cache files directly.

The command selection is:

- a profile with one valid `login_session` uses
  `aws login --profile NAME --no-cli-auto-prompt`;
- a profile with one valid `sso_account_id` uses
  `aws sso login --profile NAME --no-cli-auto-prompt`;
- a role profile requires a valid `role_arn` whose account matches the
  Authentication Context's Expected Identity, then follows its declared
  `source_profile` until it reaches one of the two supported login modes.

A direct console-login or IAM Identity Center profile must expose local account
metadata matching the Expected Identity. A source profile reached through a
role may belong to another AWS account; the selected role ARN remains the
target-account check.

Source-profile traversal is bounded to eight profiles and rejects cycles.
Profiles with ambiguous login modes, malformed or truncated metadata, an
unsupported credential source, or no supported explicit login mode fail closed
before any interactive command starts.

The preview identifies the Authentication Context, selected AWS Provider
Profile, Expected Identity, native login mode, affected native login profile,
and exact command. It never includes a `login_session` ARN, role name, browser
URL, authorization code, or provider output.

After preview and terminal flush, authmux re-resolves the material
Authentication Context and rebuilds the AWS login plan from fresh local
metadata. Any context or login-plan drift refuses the mutation. The native
login process receives the filtered authmux environment plus `AWS_PROFILE` for
the affected login profile, inherits the terminal directly, and is never
captured by authmux.

A zero native exit proves only that the supported login command completed.
Live Session Usability and the selected role or account identity remain a
separate, explicitly authorized provider-validation step, such as guarded
`authmux exec`.

## Consequences

AWS retains credential custody and can open its supported browser flow or
update only its own caches. Role-based contexts can recover their source
session without pretending that the source and target accounts are identical.

Login planning adds bounded local AWS CLI probes and requires AWS CLI v2.32.0
or later for console-login profiles. IAM Identity Center login remains
available on earlier supported AWS CLI v2 releases. Native cancellation,
failure exit codes, and signals pass through without retry or fallback.

`status`, `doctor`, and `exec` never invoke either login command implicitly.
They retain the side-effect and evidence boundaries accepted in ADR 0002.

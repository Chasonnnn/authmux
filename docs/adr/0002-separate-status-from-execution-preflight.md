# ADR 0002: Separate read-only status from execution preflight

- Status: Accepted
- Date: 2026-08-03

## Context

AWS `sts get-caller-identity` provides strong provider-validated identity
evidence. Normal AWS credential resolution may also retrieve, assume, or
automatically refresh temporary credentials and update AWS-owned caches. That
behavior is acceptable immediately before an explicitly requested child
command, but it violates authmux's contract that `status` is read-only.

Configured AWS profile metadata is weaker. The supported
`aws configure get sso_account_id --profile NAME` command can report an account
declared by an IAM Identity Center profile without reading raw configuration or
credential cache files. It cannot prove that a Session exists, is usable, or
will resolve to that account during a future service call.

## Decision

Use separate Adapter contracts for the two observations:

- guarded `exec` may call `sts get-caller-identity` as an execution preflight
  and must disclose that native credential resolution can update provider-owned
  state;
- `status` may inspect only documented local profile metadata and must never
  reuse the execution preflight;
- an account read from local metadata can produce `match` or `mismatch`, but
  Session Usability remains `indeterminate`, Reauthentication Need remains
  `unknown`, and Evidence Level is `local_metadata`;
- absent metadata produces no Observed Identity and an `unverified` Identity
  Match;
- malformed or truncated metadata becomes sanitized `provider_error` report
  data, not a guessed identity;
- a missing executable or inability to run the bounded local command remains a
  command failure.

`status` reports observation time and explicitly states that no provider was
contacted. It does not infer expiration or read provider cache files.

## Consequences

The command is honestly useful for detecting a profile-to-project account
misconfiguration, but it cannot answer whether AWS access works now. Users must
run a guarded command to obtain provider validation. The status model must
support an optional Observed Identity rather than inventing a placeholder.

The separate Status Adapter adds one Interface, justified by materially
different side-effect and evidence contracts. Future providers must classify
their local and live observations independently; a convenient live command is
not automatically acceptable for `status`.

If AWS later offers a documented no-write identity validation mechanism, it can
be evaluated as a stronger status evidence path without weakening this
boundary.

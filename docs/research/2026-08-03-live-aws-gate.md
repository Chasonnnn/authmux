# Live AWS integration gate

Date: 2026-08-03

## Result

The opt-in live AWS gate passed on macOS with AWS CLI `2.36.11` against one
user-owned profile. The test exercised the compiled authmux binary through:

1. local `doctor` checks;
2. read-only local-metadata `status`;
3. the provider-validating STS identity guard; and
4. process-scoped profile selection for `/usr/bin/true`.

The real profile name, account identifier, provider output, and native cache
contents are intentionally not retained in this repository. The temporary
authmux user configuration was removed after the run.

## Boundary

The live gate is ignored by the default suite and requires two explicit
environment variables. It captures and suppresses command output, but the AWS
CLI may refresh its provider-owned cache during STS credential resolution.

This proves one real guarded execution path. It does not yet prove concurrent
profiles sharing an IAM Identity Center session, exact expiration, failed
reauthentication, or behavior across multiple AWS organizations.

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

## Two-profile interactive recovery gate

Added 2026-08-04, the ignored
`configured_aws_login_and_two_profiles_complete_the_live_workflow` gate requires
two distinct native profile names, their Expected Identities, and explicit
acknowledgements for login and credential-resolution cache writes. It:

1. builds a temporary two-context authmux configuration;
2. runs explicit terminal-attached login for the first context;
3. runs local `doctor` and `status` for both contexts; and
4. runs the provider-validating guarded execution preflight for each profile.

The gate permits the two profiles to resolve to the same account because a
selected role and its source profile can be separate Provider Profiles without
representing separate AWS accounts. A successful run proves profile isolation
and recovery behavior, not distinct-account coverage. Distinct-account or
multi-organization coverage must compare the two provider-validated account
identifiers supplied as Expected Identities and record only the boolean result,
never the identifiers themselves.

The native browser flow inherits the terminal and bypasses test output capture.
Provider names, account identifiers, authorization URLs, codes, and cache
contents are never written to this repository.

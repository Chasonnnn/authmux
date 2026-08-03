# Build-versus-adopt benchmark

Date: 2026-08-03

## Decision

Continue the narrow AWS identity-guard slice. The benchmark found meaningful
incremental value in comparing a user-declared Expected Identity with a fresh,
provider-observed account before child execution while leaving credentials in
the native provider store.

This is not a general verdict that authmux is better than Atmos or `direnv`.
Atmos has a much broader infrastructure authentication runtime, while `direnv`
has a mature repository trust mechanism. The justified scope is only the
native-custody, fail-closed identity guard; expanding into credential
acquisition, a shell runtime, or broad infrastructure orchestration would erase
that distinction and add avoidable maintenance.

## Evidence boundary

The trials used fictional names, an empty environment, a disposable home and
XDG directories, and child marker scripts. They did not inspect a real
credential cache, call a provider API, open a browser, store a credential, or
read a real identity. Atmos telemetry was disabled for the behavioral trials,
and its keyring was set to the in-memory backend.

The first Atmos version invocation, before the behavioral isolation was
established, reported that telemetry is enabled by default and failed to load
its version-check cache under the filesystem sandbox. The subsequent trials
set `ATMOS_TELEMETRY_ENABLED=false` explicitly. This default is an adoption
consideration for a security-sensitive local CLI.

Neither Atmos, `direnv`, Granted, nor Assume was installed on the workstation.
The tested binaries were downloaded to a temporary directory, checksum
verified, executed there, and removed after the trial.

## Pinned tools

| Tool | Version | Release SHA-256 |
|---|---:|---|
| Atmos | 1.224.1 | `88e4c323f2e01f0809205048d486a3873a193e47329c604e2fb739044b7e69bb` |
| direnv | 2.37.1 | `4f569f3a36732bfd8b8fea7bfcc6ad87a59745c109022164d0ca4832451d5369` |
| authmux | `4071c43` | repository commit |

Release versions, asset URLs, and digests came from the projects' official
GitHub release metadata. The downloaded bytes matched both published digests.

## Fictional workflow

The test context selected AWS profile `fixture-expected`. A deterministic child
reported account `fixture-observed`, representing the wrong-account condition.
The observable question was whether the tool independently understood that the
two identities differed and refused to launch the protected child.

### authmux

`cargo test --test cli_exec` passed both executable behavior tests:

- a fictional `111111111111` versus `222222222222` mismatch refuses child
  execution with a sanitized diagnostic;
- a matching account launches the child and preserves its exit code.

This is deterministic contract evidence, not a claim about a live AWS session.

### Atmos

A disposable `aws/user` identity with `webflow_enabled: false` passed
`atmos auth validate`. Atmos labeled the auth command experimental. Running
`atmos auth exec --identity fixture-aws -- <marker-child>` without credentials
exited 1 and did not launch the child. It attempted interactive credential
input, then returned an explicit no-TTY authentication failure. The disposable
XDG inventory contained only Atmos cache files after the failed attempt.

This proves Atmos has an authenticated execution gate. It does not reproduce
the tested authmux workflow: Atmos's documented `aws/user` path does not consult
ambient AWS credentials and instead obtains credentials from configuration,
the keyring, or browser authentication before materializing temporary provider
files. The configured Atmos identity is therefore the credential source, not
an independent Expected Identity checked against a user-owned native profile.

The result must not be generalized to every Atmos provider or identity kind.
In particular, this trial does not prove that Atmos cannot enforce account
targeting in IAM Identity Center flows. A true live comparison would require
credentials or an AWS-compatible emulator and was intentionally outside this
no-credential gate.

### direnv plus a native-style child

Before approval, `direnv exec` refused to load the fictional `.envrc`. After
`direnv allow`, it exported `AWS_PROFILE=fixture-expected`, ran the child, and
exited 0 even though the child reported `fixture-observed`. Adding a comment to
the approved `.envrc` invalidated the approval and blocked the next run.

This is strong file-trust and environment-selection behavior. `direnv` does
not interpret provider identity, distinguish observation evidence, or compare
the selected profile with the account that the child will use.

## Capability comparison

| Capability | authmux tracer | Atmos trial | `direnv` control |
|---|---|---|---|
| Process-scoped child execution | yes | yes | yes |
| Leaves native AWS profile as credential custodian | yes | no for tested `aws/user` path | yes |
| Fresh observed-account comparison before child | yes | not represented by tested path | no |
| Blocks the fictional identity mismatch | yes | not runnable without changing custody | no |
| Repository-file trust approval | not implemented | configuration is discovered from project paths | yes |
| Broad multi-cloud auth runtime | no | yes | no |

## Recommendation and trade-off

Proceed through the remaining Phase 1 acceptance criteria, but keep the product
smaller than Atmos: add explainable context resolution, stable output, signal
parity, and read-only status semantics around the proven guard. The benefit is
native custody plus an explicit wrong-account stop. The cost is maintaining
provider observation contracts that Atmos avoids by becoming the credential
runtime and that `direnv` avoids by remaining provider-agnostic.

Re-run the gate with a disposable IAM Identity Center account before claiming
live AWS support. Pause the project if that dogfood trial shows native AWS
refresh side effects cannot meet the read-only contract, or if Atmos adds an
equivalent native-profile Expected-versus-Observed guard without assuming
credential custody.

## Primary sources

- [Atmos authentication](https://atmos.tools/cli/configuration/auth/)
- [Atmos identities](https://atmos.tools/cli/configuration/auth/identities/)
- [Atmos auth exec](https://atmos.tools/cli/commands/auth/exec/)
- [Atmos telemetry](https://atmos.tools/cli/telemetry)
- [direnv](https://direnv.net/)
- [direnv standard library](https://direnv.net/man/direnv-stdlib.1.html)

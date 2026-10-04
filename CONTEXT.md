# Authentication Context Management

This context describes how a developer selects and verifies the identities
used by local command-line tools while leaving credentials under each native
provider's custody.

## Language

**Provider**:
An authentication system whose native CLI or agent owns a developer session,
such as AWS, Google Cloud, GitHub, or SSH.
_Avoid_: Integration, backend

**Provider Identity**:
A human-recognizable identity within one provider, such as an AWS role, Google
account, GitHub user, or SSH key label.
_Avoid_: Account when the provider-specific meaning is unclear

**Provider Profile**:
A native, non-secret selector intended to resolve to a Provider Identity, such
as an AWS profile, Google Cloud configuration name, or user-owned SSH host
alias.
_Avoid_: Credential profile, secret profile

**Credential Plane**:
A distinct native authentication surface within one Provider that has its own
selection and evidence semantics, such as the gcloud CLI and Application
Default Credentials (ADC) within Google Cloud.
_Avoid_: Provider when the surfaces share one Provider but not one Session

**Expected Identity**:
The Provider Identity a developer declares as appropriate for an
Authentication Context.
_Avoid_: Configured account, assumed identity

**Observed Identity**:
The Provider Identity reported by a read-only Status Observation.
_Avoid_: Current account, actual identity

**Identity Match**:
The comparison between an Expected Identity and an Observed Identity:
`match`, `mismatch`, or `unverified`.
_Avoid_: Valid identity, trusted identity

**Authentication Context**:
A named set of Provider Profiles and Expected Identities intended to be used
together for one body of work.
_Avoid_: Workspace, environment, account bundle

**Project Binding**:
A repository-local association with a default Authentication Context and
optional per-provider login context mappings. Each mapping names an existing
user-owned Authentication Context; it contains no Provider Profile overrides.
_Avoid_: Project credential, project login

**Session**:
The provider-owned authenticated state available to a local tool for a limited
or indefinite period.
_Avoid_: Token when referring to the whole authenticated state

**Credential**:
Secret material that proves identity, including tokens, private keys, access
keys, and refresh material.
_Avoid_: Session, profile

**Credential Custody**:
Responsibility for storing, refreshing, and protecting a Credential.
_Avoid_: Secret management when only custody is meant

**Status Observation**:
A read-only, time-bounded check of what a provider safely reports about a
Session.
_Avoid_: Validation when the check cannot prove end-to-end authorization

**Session Usability**:
Whether provider evidence supports using a Session now: `usable`, `unusable`,
or `indeterminate`.
_Avoid_: Validity state, healthy, broken

**Observation Reason**:
The normalized explanation for a Session Usability conclusion, such as
`expired`, `missing`, `unreachable`, or `provider_error`.
_Avoid_: Status, failure state

**Reauthentication Need**:
Whether a Session requires explicit Reauthentication: `required`,
`not_required`, `unknown`, or `not_applicable`.
_Avoid_: Refreshable, login state

**Evidence Level**:
The strength of a Status Observation: `local_metadata`,
`provider_validation`, or `connectivity_only`.
_Avoid_: Confidence score, proof

**Reauthentication**:
An explicit user-initiated native provider flow that establishes or refreshes
a Session.
_Avoid_: Automatic login, silent refresh

**Execution Scope**:
The child-process-only environment in which an Authentication Context is
applied to a command.
_Avoid_: Global switch, active account

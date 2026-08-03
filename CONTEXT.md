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
A native, non-secret selector for a Provider Identity, such as an AWS profile
or Google Cloud configuration name.
_Avoid_: Credential profile, secret profile

**Authentication Context**:
A named set of Provider Profiles intended to be used together for one body of
work.
_Avoid_: Workspace, environment, account bundle

**Project Binding**:
A repository-local association between a project and an Authentication
Context.
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

**Validity State**:
The normalized conclusion from a Status Observation: `valid`, `expired`,
`refreshable`, `unknown`, `unreachable`, or `not_applicable`.
_Avoid_: Healthy, broken

**Reauthentication**:
An explicit user-initiated native provider flow that establishes or refreshes
a Session.
_Avoid_: Automatic login, silent refresh

**Execution Scope**:
The child-process-only environment in which an Authentication Context is
applied to a command.
_Avoid_: Global switch, active account

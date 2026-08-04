# ADR 0005: Observe an explicit SSH control socket

Status: Accepted

Date: 2026-08-03

## Context

ADR 0004 delegates SSH connection reuse to user-owned OpenSSH configuration and
prohibits authmux from reading that configuration or acting as a connection
manager. After a successful native login, users and local agents still need a
safe way to distinguish an available reusable transport from one that has
ended.

Neither a configured host alias nor an installed SSH client proves that a
control master exists. `ssh -G HOST` is unsuitable because it evaluates user
configuration, including `Match exec`. A remote no-op is stronger evidence but
contacts the provider, may create a new connection, and is not appropriate for
the default read-only `status` command.

OpenSSH supports control commands against an explicitly selected multiplexing
socket through `ssh -S PATH -O check HOST`. The native output can contain a
process identifier and is not needed for normalization.

Source: [OpenSSH client manual](https://man.openbsd.org/ssh)

## Decision

An SSH Provider Profile may declare an absolute, non-secret `control_path` in
the user-owned authmux configuration. The production status adapter accepts
the path only when it is lexically below the current user's `.ssh` directory.
It rejects parent traversal and treats symlinks, non-sockets, insecure parent
directories, ownership mismatches, and inspection failures as unknown local
evidence.

When the path is absent, authmux reports transport reuse as `inactive` without
starting OpenSSH. When a protected user-owned Unix socket exists, authmux runs
this bounded local control command with an empty SSH configuration:

```console
ssh -F /dev/null -S CONTROL_PATH -O check authmux-local-status
```

The probe has a two-second timeout and a 4 KiB output cap. Authmux discards all
stdout and stderr. Exit zero reports `active`; any nonzero, truncated, timed
out, or failed probe reports `unknown`. The command does not resolve or contact
the configured Empire AI host.

The normalized status keeps these axes separate:

- Transport Reuse: `active`, `inactive`, or `unknown`;
- Session Usability: `indeterminate`;
- Identity Match: `unverified`;
- Reauthentication Need: `unknown`;
- Evidence Level: `local_metadata`;
- provider contacted: `false`.

No expiration is reported. `ControlPersist` is an idle policy, not a
provider-reported remaining lifetime.

This decision narrowly supersedes ADR 0004's prohibition on `ssh -O`: only the
fixed, local, output-discarding `check` command above is permitted from
`status`. All other connection management remains delegated to OpenSSH.

## Consequences

Agents can ask authmux whether a reusable local transport is present without
triggering MFA, evaluating arbitrary SSH configuration, or contacting Empire
AI. An active result does not prove remote authorization or identity and may
become stale immediately after observation.

Generic `authmux exec` remains unsupported for SSH. It represents local
process-scoped provider selection, while SSH remote commands have different
execution and quoting semantics. Agents continue to use native `ssh empire`.

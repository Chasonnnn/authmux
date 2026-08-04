# ADR 0004: Delegate SSH session reuse to OpenSSH

Status: Accepted

Date: 2026-08-03

## Context

Empire AI documents interactive SSH access with multifactor authentication.
OpenSSH can reuse one authenticated transport through `ControlMaster`,
`ControlPath`, and `ControlPersist`. A duration such as `48h` or `72h` is the
idle lifetime of that local background master connection; it is not a
provider-issued Credential lifetime or a promise that the connection will
survive sleep, a network change, server termination, or revocation.

The user wants authmux to make this native convenience available without
turning authmux into an SSH credential issuer or general-purpose connection
manager. OpenSSH also documents that a control socket is an authenticated
local capability and recommends placing it in a directory that other users
cannot write.

Sources:

- [OpenSSH client configuration manual](https://man.openbsd.org/ssh_config)
- [Empire AI guidance from RIT Research Computing](https://research-computing.git-pages.rit.edu/docs/empire_ai.html)
- [Empire AI guidance from University at Buffalo CCR](https://docs.ccr.buffalo.edu/en/latest/howto/empireai/)

## Decision

authmux supports explicit native SSH login delegation:

```console
authmux login empire --provider ssh
```

Before starting OpenSSH, authmux displays the selected Authentication Context,
SSH host alias, declared Expected Identity, and literal native command. It then
spawns `ssh HOST_ALIAS` as an argument vector with the interactive terminal
attached. Native output and MFA input bypass authmux capture and logging. A
zero exit from OpenSSH proves only that the native command completed; authmux
continues to report remote Session Usability as unverified.

User-owned OpenSSH configuration remains authoritative for connection reuse.
If the selected host alias uses `ControlMaster` and `ControlPersist`, the login
may create or reuse a master connection according to OpenSSH behavior and the
server's policy. authmux does not configure, lengthen, inspect, refresh, or
promise that lifetime.

The native login command intentionally evaluates the user's SSH configuration.
That behavior is allowed only for this explicit state-changing action. The
read-only `status` and `doctor` commands retain ADR 0003's prohibition on
`ssh -G`, remote contact, and evaluation of SSH configuration.

authmux does not:

- set `ControlPersist` to an indefinite or longer duration;
- read or write `~/.ssh/config` or control-socket paths;
- issue SSH keys or certificates;
- run `ssh -O`, maintain a daemon, reconnect a dropped transport, or suppress
  provider-required MFA;
- represent a reusable transport as a valid Credential or known expiration.

## Consequences

Existing OpenSSH multiplexing works through authmux without duplicating SSH
configuration or credential custody. The explicit terminal handoff also gives
the user one place to select and preview the intended context before MFA.

Longer reuse increases the time during which a process with access to the
user's protected control socket can open another channel. It also remains
fragile across laptop sleep, network changes, and server-side limits. Users who
need durable noninteractive access must use an Empire AI-supported mechanism,
such as administrator-issued SSH certificates if offered; authmux will not
invent one.

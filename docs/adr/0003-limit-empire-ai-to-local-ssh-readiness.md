# ADR 0003: Limit Empire AI observation to local SSH readiness

- Status: Accepted
- Date: 2026-08-03

## Context

Empire AI access is an institutional SSH workflow. Current institutional
guidance requires an SSH client and documents interactive multifactor
authentication, but the published login hostname differs across institutions
and cluster generations. A host, username, loaded key, or successful TCP
connection does not independently prove the remote Provider Identity,
authorization, MFA state, or future Session expiry.

OpenSSH `ssh -V` displays the client version and exits. It does not need a
destination, inspect an authentication agent, or contact a remote system.
`ssh -G HOST` is not an equivalent read-only probe: it evaluates `Host` and
`Match` blocks, and `Match exec` runs a command under the user's shell. Its
expanded output can also contain usernames, paths, proxy commands, and other
sensitive metadata.

Sources:

- [OpenSSH client manual](https://man.openbsd.org/ssh)
- [OpenSSH client configuration manual](https://man.openbsd.org/ssh_config)
- [Empire AI guidance from University at Buffalo CCR](https://docs.ccr.buffalo.edu/en/latest/howto/empireai/)
- [Empire AI guidance from RIT Research Computing](https://research-computing.git-pages.rit.edu/docs/empire_ai.html)

## Decision

The first Empire AI slice is a bounded local-readiness Module:

- invoke only `ssh -V` through the secure process runner with a two-second
  timeout, a 4 KiB output cap, and no provider selector;
- narrowly retain only a recognized OpenSSH version and discard the remaining
  runtime metadata;
- report that no provider was contacted;
- treat malformed, truncated, nonzero, or unavailable-client results as
  sanitized failures without retaining native output;
- do not run `ssh -G`, `ssh-add`, DNS, TCP, remote commands, or interactive SSH
  from this Module;
- do not infer an Observed Identity, Identity Match, Session Usability,
  Reauthentication Need, MFA state, or expiration from local readiness.

Empire AI host alias and Expected Identity are accepted in user configuration
and can be inspected without invoking OpenSSH. CLI `doctor` integration and
explicit interactive terminal handoff require separate behavior slices.
Hostnames remain user configuration and are never hardcoded from
institution-specific documentation. SSH-only `status` and `exec` fail before
provider observation or child execution because no remote evidence or safe
Execution Scope exists yet.

## Consequences

This first slice can prove that a supported OpenSSH client is installed without
triggering MFA or executing commands embedded in SSH configuration. It cannot
say whether Empire AI is reachable or whether the user can log in.

The trade-off is deliberately limited immediate utility. It preserves the
read-only contract and creates a safe readiness Module before authmux
generalizes its currently AWS-shaped Authentication Context and presentation
paths.

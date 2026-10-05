---
status: accepted
---

# Handoff interactive login outside captured agent sessions

## Context

Native login output bypasses authmux capture when authmux inherits a terminal,
but Codex, Claude, CI, and other outer process supervisors can still record the
entire terminal stream. Browser URLs, device codes, MFA prompts, and native
diagnostics therefore appeared in retained agent transcripts even though
authmux itself did not store them.

Routine agent workflows also added `context show` and `status` before guarded
execution. Those checks duplicate work already owned by `exec` and increase
approval and retry friction without strengthening its provider guard.

## Decision

`authmux login CONTEXT --provider PROVIDER --print-command` performs normal
configuration resolution and provider-specific login planning, prints the
existing sanitized preview plus an external-terminal handoff, and exits zero
without starting the native provider command.

Captured agents use this non-executing mode and stop. The user reruns the same
`authmux login` without `--print-command` in a separate user-controlled terminal
and confirms completion; the agent then retries the original guarded command
once. Keeping authmux in the external path preserves provider selectors that
are intentionally omitted from the sanitized native-command preview. The agent
does not request login output, browser URLs, authorization codes, passwords, or
MFA values.

The handoff names a separate terminal application, such as Terminal, iTerm,
or Ghostty. Codex or Claude chat shell commands remain captured even when the
user starts them. They are not an external-terminal handoff.

Native login success leaves the original operation pending. After user
confirmation, the agent retries its preserved argument vector once and reports
the substantive result. Recovery is complete only if that guarded operation
succeeds. Authmux does not launch a terminal or automatically resume the agent.

For normal bound-project work, agents invoke the leaf operation through
`authmux exec` directly. They use `context show` once when project intent is
unfamiliar or changed, and reserve `status` and `doctor` for overview or
diagnosis. Approval rules are scoped to the guarded leaf-command family, not
to every authmux subcommand.

## Consequences

The handoff removes interactive provider output from the agent-owned process
tree and makes the common path one guarded command. Authmux cannot automatically
observe native completion in this mode, so the workflow requires one explicit
user confirmation and a retry of the intended operation. Direct interactive
`authmux login` remains available in a user-controlled terminal.

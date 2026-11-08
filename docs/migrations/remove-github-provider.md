# Remove GitHub Provider Profiles

Authmux supports AWS, Google Cloud, and SSH. GitHub CLI uses native authentication.
Configuration stays at version 1. Files without GitHub settings remain valid.

1. Remove each `[contexts.NAME.providers.github]` table from the user configuration.
2. Remove any context that has no remaining Provider Profile, including its metadata.
3. Remove `github` entries from repository `[project.providers]` tables.
4. Point `project.context` to a remaining context when it named a removed context.
5. Replace wrapped GitHub commands and login shortcuts with native GitHub CLI commands.

| Retired command | Replacement |
|---|---|
| `authmux exec --context NAME -- gh pr list` | `gh pr list` |
| `authmux gh` or `authmux login NAME --provider github` | Native `gh auth login` in a separate terminal app |
| `authmux status --provider github` | Native `gh auth status` |
| `authmux doctor --provider github` | Native GitHub CLI diagnostics |

If GitHub used a separate native configuration directory, explicitly select
that directory when running `gh`. Verify the intended native login before work.
Authmux does not copy credentials, change native configuration, or select an
ambient GitHub identity during this migration.

Old user profiles fail with a sanitized error listing supported providers.
Old project mappings fail with the supported mapping names. Wrapped `gh`
commands fail before configuration loading or cloud probes and instruct the
caller to run `gh` directly.

The `exec-event-v1` schema now allows only AWS events. Status and context-list
schema versions remain unchanged. Update agent guidance to run `gh` directly.

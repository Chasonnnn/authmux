---
status: accepted
---

# Delegate credential custody to native providers

`authmux` will orchestrate native authentication tools instead of storing,
issuing, brokering, or synchronizing credentials itself. This keeps AWS,
Google Cloud, GitHub, SSH, and future providers responsible for their own
security-sensitive state while `authmux` supplies normalized status,
user-initiated reauthentication, project binding, and process-scoped
selection. The trade-off is that provider behavior cannot be perfectly
uniform and some expiry information will remain `unknown`; we accept that
honest limitation rather than create a second secret store or OAuth authority.

## Considered options

- Build an encrypted local vault: rejected because secure storage, recovery,
  rotation, and provider-specific refresh would dominate the product.
- Use Infisical or OpenBao as the core: rejected because they solve secret
  distribution and dynamic credentials, while this project primarily needs
  local identity selection and session observability.
- Wrap native tools without a normalized model: rejected because it would not
  provide a coherent cross-provider status or project-context experience.

## Consequences

- Configuration may contain only non-secret references and display metadata.
- Native provider output is treated as untrusted and potentially sensitive.
- An adapter may report uncertainty; it must never invent an expiration time.
- Interactive login is explicit and runs through the provider's supported CLI.
- Automatic refresh is allowed only when the native provider performs it under
  its own documented behavior and the user initiated the operation.

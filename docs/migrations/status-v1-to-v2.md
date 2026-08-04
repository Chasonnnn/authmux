# Status JSON migration: version 1 to version 2

Status schema version 2 adds the required `transport_reuse` field to every
observation:

- AWS and other providers without a reusable transport report `null`.
- SSH reports `active`, `inactive`, or `unknown` from protected local
  control-socket evidence.

Consumers must select behavior from `schema_version` before decoding an
observation. Version 1 remains documented in `docs/schemas/status-v1.schema.json`;
authmux now emits version 2 according to `docs/schemas/status-v2.schema.json`.

The new field does not change the meaning of `session_usability`,
`identity_match`, `reauthentication_need`, or `evidence_level`. In particular,
an active SSH transport does not make Session Usability `usable` and does not
establish an Observed Identity.

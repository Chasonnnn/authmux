# Status JSON migration: version 2 to version 3

Status schema version 3 supports multiple independent credential planes in one
provider observation report. Every observation adds these required fields:

- `credential_plane` is `gcloud_cli`, `adc`, or `null` for providers without
  separate planes;
- `expected_source_identity`, `observed_source_identity`, and
  `source_identity_match` describe an optional impersonation source;
- `expected_project`, `observed_project`, and `project_match` describe an
  optional GCP project default without treating it as an identity.

Fields that do not apply are serialized as `null`. Consumers must select the
decoder from `schema_version`; authmux now emits version 3 according to
`docs/schemas/status-v3.schema.json`. Versions 1 and 2 remain documented.

The new fields do not strengthen Session Usability or Evidence Level. In
particular, matching gcloud configuration metadata remains local evidence and
does not establish that a credential exists, can refresh, or is authorized.

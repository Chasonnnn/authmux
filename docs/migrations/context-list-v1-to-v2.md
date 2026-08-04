# Context-list JSON migration: version 1 to version 2

Context-list schema version 2 adds the required `credential_plane` field to
each provider reference. Google Cloud uses `gcloud_cli` and `adc`; providers
without separate credential planes serialize `null`.

Consumers must select the decoder from `schema_version`. authmux now emits
version 2 according to `docs/schemas/context-list-v2.schema.json`; version 1
remains documented.

# Live Google Cloud local-observation gate

Date: 2026-08-03

This opt-in gate exercises one user-owned authmux GCP context without running
gcloud, opening a credential database, opening the ADC file, printing a token,
or contacting a Google Cloud API.

```console
AUTHMUX_LIVE_GCP_CONTEXT=crm \
cargo test --test live_gcp -- --ignored --exact \
  configured_gcp_context_completes_the_live_local_workflow
```

The gate requires every GCP observation to remain `local_metadata`,
`indeterminate`, and `provider_contacted: false`. An observed identity mismatch
or failed doctor check fails the gate. Context, principal, project, and path
values are neither printed nor retained by the test.

This verifies local selection consistency only. It does not prove that a
credential exists, can refresh, authorizes any resource, or has a known expiry.

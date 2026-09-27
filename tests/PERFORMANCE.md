# Performance regression coverage

These regression cases exercise temporary databases, temporary certificate files, mock DNS/TrueLog endpoints, and a client daemon child process. They do not modify installed services or retained WORM data. They verify behavior and bounded work, not throughput measurements.

| FIXED item | Test cases | Expected behavior |
| --- | --- | --- |
| 10 | `dns_wait_releases_service_lock_and_acknowledges_only_success`; `truelog_wait_releases_lock_and_completed_event_is_not_resubmitted` | The service mutex is available while external delivery waits. Work remains pending until acknowledgement; completed work is not resubmitted. |
| 10 | `background_delivery_defers_external_tools_but_publishes_revocation` | Unavailable external tools do not prevent issuance or immediate CRL publication. |
| 11 | `cached_tls_keeps_metadata_checks_without_reopening_keys` | Repeated connections reuse the same TLS configuration without decrypting keys again; revocation and expiry still reject access. |
| 11 | `tls_cache_reloads_changed_fingerprint_and_rejects_broken_replacement` | A changed fingerprint replaces the cached configuration. A missing replacement key fails instead of falling back silently. |
| 12 | `client_relays_overlap_and_keep_credentials_separate_with_cached_trust` | A blocked remote request does not prevent another from reaching the server. Credentials remain isolated, and removal of the startup trust file does not break requests. |
| 12 | `client_caps_relays_at_sixteen_and_recovers_slots` | Sixteen requests can be in flight; overflow is rejected; completed requests release capacity. |
| 13 | `pending_delivery_batches_advance_past_uncompleted_rows`; `failed_external_delivery_stays_pending_and_later_work_can_complete` | Batches contain at most 64 jobs, advance beyond failed jobs, and retain failed work for retry. |
| 13 | `outbox_filters_completed_rows_and_separates_crl_work` | Completed rows are excluded, CRL work is separate from external work, and pending indexes exist. |
| 14 | `ca_lineage_keeps_crl_numbers_and_revocations_across_generations` | Revocation and expiry refresh each advance a linked lineage's CRL number exactly once, preserving cumulative revocations. |
| 14 | `failed_crl_publications_coalesce_and_retry_independently_of_external_delivery` | Multiple failed revocations queue one lineage publication. Retry succeeds despite unavailable TrueLog, retaining both revocations. |

Run the standard gate when build and test execution is required:

```sh
./scripts/check/panic-gate.sh
```

The gate uses the project build runner and increments VERSION for compilation attempts. These cases run as part of the Rust library and lifecycle suites. `tests/post-test.sh` prints installed server/client versions and runs installed CLI checks, eight-caller status/info checks, and the accumulated isolated regression cases listed above. Run it without a version argument:

```sh
./tests/post-test.sh
```

Isolated cases are labeled `Isolated` and use prebuilt Rust executables under `target/debug/deps`, not installed service data. Missing or older-than-source test executables produce FAIL with rebuild guidance; the script never compiles automatically. The optional expected-version argument remains available for compatibility.


| FIXED item | Additional cases | Expected behavior |
| --- | --- | --- |
| 15 | `ocsp_cache_avoids_unrelated_pem_reads_and_observes_live_revocation`; `ocsp_cache_refreshes_after_intermediate_renewal` | Public issuer identities are reused, live revocation is visible, and renewed CA certificates refresh the cache. |
| 16 | `dns_index_allows_renewal_but_blocks_new_issuance_and_finds_aliases` | Same-CN/DNS renewal succeeds; new duplicates fail; case-insensitive and multi-name lookups remain supported. |
| 17 | `paginated_lists_bound_memory_preserve_order_and_exclude_new_rows` | Each page has at most 256 rows; output is ordered with one header, and later inserts are excluded by the initial upper bound. |
| 18 | `binary_frames_round_trip_bytes_without_json_expansion`; `legacy_frames_keep_response_format_and_binary_frames_do_not_consume_next` | Binary bodies remain exact, oversized/truncated frames fail, and legacy JSON callers receive JSON replies. |

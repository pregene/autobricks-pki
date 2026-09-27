"""Run prebuilt isolated regression cases without compiling or changing VERSION."""
import os
from pathlib import Path

CASES = [
    ('autobricks_pki', 'server::delivery::tests::dns_wait_releases_service_lock_and_acknowledges_only_success', 'FIXED-10 DNS wait releases server lock'),
    ('autobricks_pki', 'server::delivery::tests::truelog_wait_releases_lock_and_completed_event_is_not_resubmitted', 'FIXED-10 TrueLog wait releases lock; no completed-event retry'),
    ('lifecycle', 'background_delivery_defers_external_tools_but_publishes_revocation', 'FIXED-10 External delivery does not block revocation publication'),
    ('lifecycle', 'cached_tls_keeps_metadata_checks_without_reopening_keys', 'FIXED-11 TLS cache reuse preserves revocation and expiry checks'),
    ('lifecycle', 'tls_cache_reloads_changed_fingerprint_and_rejects_broken_replacement', 'FIXED-11 TLS replacement reload and broken-key rejection'),
    ('lifecycle', 'client_performance::client_relays_overlap_and_keep_credentials_separate_with_cached_trust', 'FIXED-12 Concurrent relay credentials remain isolated'),
    ('lifecycle', 'client_performance::client_caps_relays_at_sixteen_and_recovers_slots', 'FIXED-12 Relay limit of 16 and slot recovery'),
    ('lifecycle', 'pending_delivery_batches_advance_past_uncompleted_rows', 'FIXED-13 Outbox batches advance in groups of 64'),
    ('autobricks_pki', 'server::delivery::tests::failed_external_delivery_stays_pending_and_later_work_can_complete', 'FIXED-13 Failed delivery remains pending; later jobs proceed'),
    ('lifecycle', 'outbox_filters_completed_rows_and_separates_crl_work', 'FIXED-13 Completed-job filtering and separate CRL queue'),
    ('lifecycle', 'ca_lineage_keeps_crl_numbers_and_revocations_across_generations', 'FIXED-14 One CRL publication per renewed CA lineage'),
    ('lifecycle', 'failed_crl_publications_coalesce_and_retry_independently_of_external_delivery', 'FIXED-14 Failed CRLs coalesce and retry without TrueLog'),
    ('lifecycle', 'ocsp_cache_avoids_unrelated_pem_reads_and_observes_live_revocation', 'FIXED-15 OCSP cache avoids unrelated reads; revocation stays current'),
    ('lifecycle', 'ocsp_cache_refreshes_after_intermediate_renewal', 'FIXED-15 OCSP cache refresh after Intermediate CA renewal'),
    ('lifecycle', 'dns_index_allows_renewal_but_blocks_new_issuance_and_finds_aliases', 'FIXED-16 Same CN/DNS renewal succeeds; duplicate issuance rejected'),
    ('lifecycle', 'paginated_lists_bound_memory_preserve_order_and_exclude_new_rows', 'FIXED-17 Bounded list pages preserve order and snapshot boundary'),
    ('management', 'binary_frames_round_trip_bytes_without_json_expansion', 'FIXED-18 Binary frames preserve bytes and enforce size limits'),
    ('management', 'legacy_frames_keep_response_format_and_binary_frames_do_not_consume_next', 'FIXED-18 Legacy reply compatibility and frame boundaries'),
]


def execute(project, test, run, require):
    print('Isolated regression checks: prebuilt Rust tests with temporary fixtures.', flush=True)
    print('These checks exercise build artifacts, not the installed database.', flush=True)
    sources = list((project / 'src').rglob('*.rs')) + list((project / 'tests').rglob('*.rs'))
    sources += list((project / 'src').rglob('*.sql'))
    sources += [project / 'Cargo.toml', project / 'Cargo.lock']
    newest_source = max(path.stat().st_mtime_ns for path in sources)
    binaries = {}

    def case(suite, name):
        if suite not in binaries:
            candidates = [path for path in (project / 'target/debug/deps').glob(suite + '-*')
                          if path.is_file() and os.access(path, os.X_OK) and not path.suffix]
            require(bool(candidates), 'Missing regression executable; run the panic gate first')
            binary = max(candidates, key=lambda path: path.stat().st_mtime_ns)
            require(binary.stat().st_mtime_ns >= newest_source,
                    'Regression executable predates source changes; rebuild with the panic gate')
            listing = run([str(binary), '--list']).stdout
            binaries[suite] = (binary, listing)
        binary, listing = binaries[suite]
        require(name + ': test' in listing.splitlines(), 'Required regression case is missing: ' + name)
        result = run([str(binary), '--exact', name, '--nocapture'], success=False)
        require(result.returncode == 0 and '1 passed; 0 failed;' in result.stdout,
                (result.stdout + '\n' + result.stderr).strip())

    for suite, name, purpose in CASES:
        test('Isolated ' + purpose, lambda suite=suite, name=name: case(suite, name))

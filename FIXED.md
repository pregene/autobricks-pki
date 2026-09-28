# Issue corrections

| No. | Discovery date | Current version | Issue | Fix version | Fix date |
| --- | --- | --- | --- | --- | --- |
| 1 | 2026-09-28 | 1.0.102 | Single-certificate lookup loaded all files and keys; replaced with a fingerprint-filtered query and target-only loading. | 1.0.105 | 2026-09-28 |
| 2 | 2026-09-28 | 1.0.102 | Issuer lookup filtered all certificates; replaced with exact fingerprint lookup followed by CN lookup with ordering and LIMIT 1. | 1.0.105 | 2026-09-28 |
| 3 | 2026-09-28 | 1.0.102 | Root lookup loaded all certificates; replaced with a kind-filtered identifier query and separate public/signing access. | 1.0.105 | 2026-09-28 |
| 4 | 2026-09-28 | 1.0.102 | TLS and chain lookup repeated full loading; now load only the TLS signing key and public issuer/root certificates. | 1.0.105 | 2026-09-28 |
| 5 | 2026-09-28 | 1.0.102 | Status checks loaded all files and keys; now select revoked_at by fingerprint without file I/O. | 1.0.105 | 2026-09-28 |
| 6 | 2026-09-28 | 1.0.102 | OCSP loaded all files and keys; now matches public CA candidates, queries lineage-scoped issuer/serial metadata, and loads only the selected signing key. | 1.0.105 | 2026-09-28 |
| 7 | 2026-09-28 | 1.0.102 | DNS collision checks loaded certificate/key files; now read server profiles only and skip this work for client-only issuance. | 1.0.105 | 2026-09-28 |
| 8 | 2026-09-28 | 1.0.102 | Renewal selection loaded unrelated files; now uses SQL-filtered due CA metadata, exact leaf metadata, and targeted issuer selection. | 1.0.105 | 2026-09-28 |
| 9 | 2026-09-28 | 1.0.102 | CRL/audit processing loaded unrelated files; now uses lineage public CAs and revoked serial metadata, with a Root identifier-only audit lookup. | 1.0.105 | 2026-09-28 |
| 10 | 2026-09-28 | 1.0.105 | High: external DNS/TrueLog delivery moved to a dedicated worker; I/O runs outside the service lock. | 1.0.108 | 2026-09-28 |
| 11 | 2026-09-28 | 1.0.105 | High: server TLS configuration is cached by certificate fingerprint; every connection retains metadata revocation/expiry checks. | 1.0.108 | 2026-09-28 |
| 12 | 2026-09-28 | 1.0.105 | High: client trust configuration is reused and relays are bounded to 16 concurrent requests. TCP connections remain per-request. | 1.0.108 | 2026-09-28 |
| 13 | 2026-09-28 | 1.0.105 | High: partial pending-work indexes and 64-row cursor batches replace unbounded external polling; completed rows remain retained. | 1.0.108 | 2026-09-28 |
| 14 | 2026-09-28 | 1.0.105 | High: CRL tasks are coalesced by renewal lineage; revocation and expiry refresh publish once for linked generations. | 1.0.108 | 2026-09-28 |
| 15 | 2026-09-28 | 1.0.105 | Medium: OCSP caches public issuer identity hashes, refreshes on CA generation changes, parses each request once, and queries live status. | 1.0.111 | 2026-09-28 |
| 16 | 2026-09-28 | 1.0.105 | Medium: non-unique DNS expression indexes replace profile scans; same-CN/DNS renewal remains allowed and legacy aliases remain checked. | 1.0.111 | 2026-09-28 |
| 17 | 2026-09-28 | 1.0.105 | Medium: idx cursor pages return at most 256 certificates and CLI output streams each page with a fixed upper bound. | 1.0.111 | 2026-09-28 |
| 18 | 2026-09-28 | 1.0.105 | Medium: ABP1 length-prefixed framing sends raw bodies without JSON byte-array expansion; legacy requests receive legacy replies. | 1.0.111 | 2026-09-28 |
| 19 | 2026-09-28 | 1.0.111 | Leaf lists lack status selectors; added default VALID, revoked/REVOKED, renew/SUPERSEDED, and all filters with indexed pagination. | 1.0.114 | 2026-09-28 |
| 20 | 2026-09-28 | 1.0.111 | Intermediate CA lists lack state filters; added default VALID, revoked/REVOKED, renew/SUPERSEDED, and all filters with indexed pagination. | 1.0.114 | 2026-09-28 |
| 21 | 2026-09-28 | 1.0.111 | Intermediate CA renewal used the leaf seven-day window, limiting 47-day leaf issuance near CA expiry; separated the CA window to 48 days while retaining seven days for leaves. | 1.0.114 | 2026-09-28 |
| 22 | 2026-09-28 | 1.0.111 | ADMIN CA renew marks VALID as SUPERSEDED without issuance; the server creates the replacement internally and preserves its original duration. | 1.0.114 | 2026-09-28 |
| 23 | 2026-09-28 | 1.0.111 | ADMIN leaf renew marks VALID as SUPERSEDED without issuance; normal token-authorized renewal polls state and only issues for SUPERSEDED. | 1.0.114 | 2026-09-28 |
| 24 | 2026-09-28 | 1.0.111 | SUPERSEDED lifecycle records automatic/admin transitions and retires leaves after seven days and Intermediate CAs after 48 days, independent of renewal/download completion. | 1.0.114 | 2026-09-28 |
| 25 | 2026-09-28 | 1.0.117 | Generated-key profiles lacked extended field encoding; added DN/SAN/extensions, explicit critical flags, renewal preservation, and certificate read-back regression coverage. CSR input remains outside this implementation. | 1.0.126 | 2026-09-28 |
| 26 | 2026-09-28 | 1.0.127 | Unescaped semicolons in the leaf creation sequence diagram caused a Mermaid parse error; escaped message punctuation and verified the original failure and corrected diagram with the Mermaid parser. | 1.0.127 (documentation) | 2026-09-28 |

CREATE TABLE IF NOT EXISTS settings (
    name TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS certificates (
    idx INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    cn TEXT NOT NULL,
    kind TEXT NOT NULL,
    issuer TEXT REFERENCES certificates(fingerprint),
    serial TEXT NOT NULL,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    certificate_path TEXT NOT NULL,
    private_key_path TEXT NOT NULL,
    previous_certificate_idx INTEGER REFERENCES certificates(idx),
    valid TEXT NOT NULL DEFAULT 'VALID'
        CHECK (valid IN ('VALID', 'REVOKED', 'SUPERSEDED')),
    superseded_at INTEGER,
    revoked_at INTEGER,
    profile TEXT,
    download_hash BLOB,
    UNIQUE (issuer, serial)
);

CREATE TABLE IF NOT EXISTS intermediate_leaf (
    idx INTEGER PRIMARY KEY AUTOINCREMENT,
    intermediate_idx INTEGER NOT NULL REFERENCES certificates(idx),
    leaf_idx INTEGER NOT NULL UNIQUE REFERENCES certificates(idx),
    CHECK (intermediate_idx <> leaf_idx)
);

CREATE INDEX IF NOT EXISTS intermediate_leaf_issuer
    ON intermediate_leaf (intermediate_idx, leaf_idx);

CREATE TABLE IF NOT EXISTS crls (
    idx INTEGER PRIMARY KEY AUTOINCREMENT,
    issuer INTEGER NOT NULL UNIQUE REFERENCES certificates(idx),
    crl_path TEXT NOT NULL,
    next_update INTEGER NOT NULL,
    number INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    done INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS certificates_kind_cn_expiry
    ON certificates (kind, cn, not_after DESC, idx DESC);
CREATE INDEX IF NOT EXISTS certificates_kind_expiry
    ON certificates (kind, not_after);
CREATE INDEX IF NOT EXISTS certificates_predecessor
    ON certificates (previous_certificate_idx);
CREATE INDEX IF NOT EXISTS certificates_lower_cn
    ON certificates (lower(cn));

CREATE INDEX IF NOT EXISTS outbox_pending_id
    ON outbox (id) WHERE done=0;
CREATE INDEX IF NOT EXISTS outbox_pending_kind_payload
    ON outbox (kind, payload) WHERE done=0;

CREATE INDEX IF NOT EXISTS certificates_dns_name
    ON certificates (json_extract(profile,'$.dns_names[0]') COLLATE NOCASE)
    WHERE kind IN ('server','server-and-client');
CREATE INDEX IF NOT EXISTS certificates_dns_aliases
    ON certificates (idx)
    WHERE kind IN ('server','server-and-client') AND json_array_length(profile,'$.dns_names')>1;
CREATE INDEX IF NOT EXISTS certificates_kind_idx ON certificates (kind, idx);

CREATE INDEX IF NOT EXISTS certificates_leaf_state_idx ON certificates (valid, idx)
    WHERE kind IN ('server','client','server-and-client');

CREATE INDEX IF NOT EXISTS certificates_intermediate_state_idx ON certificates (valid, idx)
    WHERE kind='intermediate';

CREATE INDEX IF NOT EXISTS certificates_superseded_deadline ON certificates (superseded_at, idx)
    WHERE valid='SUPERSEDED' AND revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS certificates_leaf_renewal_due ON certificates (not_after, idx)
    WHERE kind IN ('server','client','server-and-client') AND valid='VALID' AND revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS certificates_extended_leaf_state_idx ON certificates (valid, idx)
    WHERE kind IN ('server','client','server-and-client','leaf');

CREATE INDEX IF NOT EXISTS certificates_extended_leaf_renewal_due ON certificates (not_after, idx)
    WHERE kind IN ('server','client','server-and-client','leaf') AND valid='VALID' AND revoked_at IS NULL;

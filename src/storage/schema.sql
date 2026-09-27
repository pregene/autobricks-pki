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
    pem BLOB NOT NULL,
    next_update INTEGER NOT NULL,
    number INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    done INTEGER NOT NULL DEFAULT 0
);

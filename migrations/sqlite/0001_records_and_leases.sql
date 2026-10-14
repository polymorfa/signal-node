-- SPDX-License-Identifier: AGPL-3.0-only
-- Sealed Signal records and per-session leases for signal-node.

-- One row per session (scope). The generation only ever increases; a record
-- write applies only while its fence generation equals this row's.
CREATE TABLE signal_leases (
    scope          TEXT     PRIMARY KEY NOT NULL,
    -- Empty after a release.
    holder         TEXT     NOT NULL,
    generation     INTEGER  NOT NULL CHECK (generation > 0),
    expires_at_ms  INTEGER  NOT NULL
) STRICT;

-- Values are sealed (AES-256-GCM) before they reach the database. Keys are
-- BLOBs so they can hold any character and sort in byte order.
CREATE TABLE signal_records (
    scope  TEXT  NOT NULL,
    ns     TEXT  NOT NULL,
    key    BLOB  NOT NULL,
    value  BLOB  NOT NULL,
    PRIMARY KEY (scope, ns, key)
) STRICT, WITHOUT ROWID;

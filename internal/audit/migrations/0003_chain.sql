-- 0003_chain: a hash chain over every recorded call, so that editing or
-- deleting a row after the fact shows up in `agentgate verify`; the labels a
-- call earned its session; and a snapshot of the tool catalog in force.
ALTER TABLE calls ADD COLUMN labels TEXT NOT NULL DEFAULT '';
ALTER TABLE calls ADD COLUMN catalog_hash TEXT NOT NULL DEFAULT '';
-- seq is NULL on rows written before the chain existed.
ALTER TABLE calls ADD COLUMN seq INTEGER;
ALTER TABLE calls ADD COLUMN prev_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE calls ADD COLUMN row_hash TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX calls_seq ON calls (seq) WHERE seq IS NOT NULL;

-- When retention removes the start of the chain, the last removed link is
-- kept here so the rest still verifies.
CREATE TABLE chain_anchor (
    id        INTEGER PRIMARY KEY CHECK (id = 1),
    seq       INTEGER NOT NULL,
    hash      TEXT NOT NULL,
    pruned_at INTEGER NOT NULL
);

-- Tool catalogs, stored once per distinct content.
CREATE TABLE catalogs (
    hash       TEXT PRIMARY KEY,
    json       TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
ALTER TABLE sessions ADD COLUMN catalog_hash TEXT NOT NULL DEFAULT '';

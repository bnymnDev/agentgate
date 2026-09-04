-- 0001_init: sessions and calls.
CREATE TABLE sessions (
    id                   TEXT PRIMARY KEY,
    started_at           INTEGER NOT NULL,
    ended_at             INTEGER,
    host_name            TEXT NOT NULL DEFAULT '',
    host_version         TEXT NOT NULL DEFAULT '',
    downstream_transport TEXT NOT NULL DEFAULT ''
);

CREATE TABLE calls (
    id               TEXT PRIMARY KEY,
    session_id       TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    ts               INTEGER NOT NULL,
    upstream         TEXT NOT NULL DEFAULT '',
    tool             TEXT NOT NULL DEFAULT '',
    args_json        TEXT NOT NULL DEFAULT '',
    args_hash        TEXT NOT NULL DEFAULT '',
    decision         TEXT NOT NULL DEFAULT '',
    rule_id          TEXT NOT NULL DEFAULT '',
    reason           TEXT NOT NULL DEFAULT '',
    result_json      TEXT NOT NULL DEFAULT '',
    result_hash      TEXT NOT NULL DEFAULT '',
    is_error         INTEGER NOT NULL DEFAULT 0,
    duration_ms      INTEGER NOT NULL DEFAULT 0,
    tokens_est       INTEGER NOT NULL DEFAULT 0,
    result_truncated INTEGER NOT NULL DEFAULT 0,
    error            TEXT NOT NULL DEFAULT ''
);

CREATE INDEX calls_session_ts ON calls (session_id, ts);
CREATE INDEX calls_ts ON calls (ts);
CREATE INDEX calls_tool ON calls (tool);
CREATE INDEX sessions_started_at ON sessions (started_at);

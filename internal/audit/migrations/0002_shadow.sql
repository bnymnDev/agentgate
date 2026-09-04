-- 0002_shadow: shadow-mode decisions are recorded as what they would have been,
-- with this flag saying the call was forwarded regardless.
ALTER TABLE calls ADD COLUMN shadow INTEGER NOT NULL DEFAULT 0;
CREATE INDEX calls_decision ON calls (decision);

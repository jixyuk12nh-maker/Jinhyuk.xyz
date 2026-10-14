PRAGMA foreign_keys = ON;
-- access_logs gets a write on almost every request (page views, logins, signups, admin
-- actions) and is read on the hot path of every login/signup to enforce the brute-force
-- lockouts in countFailures(). Without indexes matching those exact lookups, every one of
-- those reads becomes a full table scan that gets slower as the table grows, which is what
-- eventually makes D1 queries time out under load ("database 터짐"). These match the actual
-- WHERE clauses used in src/index.js:
--   countFailures() by account: WHERE event=? AND outcome='failed' AND reason=? AND created_at>?
--   countFailures() by ip:      WHERE ip=? AND event=? AND outcome='failed' AND created_at>? (already
--                                covered by access_logs_ip_idx, kept here for outcome too)
--   /api/admin/overview failed24h: WHERE created_at>? AND outcome='failed'
CREATE INDEX IF NOT EXISTS access_logs_event_reason_idx ON access_logs(event, reason, created_at DESC);
CREATE INDEX IF NOT EXISTS access_logs_outcome_created_idx ON access_logs(outcome, created_at DESC);

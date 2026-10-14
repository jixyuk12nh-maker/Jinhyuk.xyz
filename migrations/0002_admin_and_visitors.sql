PRAGMA foreign_keys = ON;
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user';
ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE users ADD COLUMN last_ip TEXT;
ALTER TABLE users ADD COLUMN last_login_at INTEGER;
CREATE INDEX IF NOT EXISTS users_role_status_idx ON users(role,status);
CREATE TABLE IF NOT EXISTS access_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  event TEXT NOT NULL,
  outcome TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS access_logs_created_idx ON access_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS access_logs_ip_idx ON access_logs(ip,created_at DESC);
CREATE TABLE IF NOT EXISTS ip_blacklist (
  ip TEXT PRIMARY KEY,
  reason TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  created_by TEXT NOT NULL
);

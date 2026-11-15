CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  owner_hash TEXT NOT NULL,
  client_hash TEXT NOT NULL,
  state TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  uploads_json TEXT NOT NULL,
  error TEXT,
  app_info_json TEXT
);
CREATE INDEX IF NOT EXISTS jobs_expiry_idx ON jobs(expires_at);

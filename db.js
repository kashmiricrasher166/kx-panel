const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');

const DATA = path.join(__dirname, 'data');
fs.mkdirSync(DATA, { recursive: true });

const db = new Database(path.join(DATA, 'kx.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT, ip TEXT, user TEXT, platform TEXT, arch TEXT, node TEXT,
    cwd TEXT, project_root TEXT, first_seen INTEGER, last_seen INTEGER,
    installs INTEGER DEFAULT 0, UNIQUE(host, ip)
  );
  CREATE TABLE IF NOT EXISTS drops (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER, ts INTEGER, kind TEXT, label TEXT,
    folder TEXT, file TEXT, size INTEGER,
    FOREIGN KEY(host_id) REFERENCES hosts(id)
  );
  CREATE INDEX IF NOT EXISTS idx_drops_host ON drops(host_id);
  CREATE INDEX IF NOT EXISTS idx_drops_ts ON drops(ts DESC);
`);

module.exports = db;

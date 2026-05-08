/**
 * Quickfire License Server
 * 
 * Endpoints:
 *   POST /activate        — activate a key on a device (binds key to hwid)
 *   POST /validate        — check if a key+hwid combo is still valid
 *   POST /admin/generate  — generate new keys (requires ADMIN_SECRET header)
 *   POST /admin/revoke    — revoke a key
 *   GET  /admin/keys      — list all keys with status
 *   GET  /health          — health check
 *
 * All admin routes require the header:  X-Admin-Secret: <your secret>
 * Set ADMIN_SECRET in environment or it defaults to a value in this file.
 */

const express  = require('express');
const Database = require('better-sqlite3');
const crypto   = require('crypto');
const cors     = require('cors');
const path     = require('path');
const fs       = require('fs');

// ── Config ────────────────────────────────────────────────────────────────────
const PORT         = process.env.PORT         || 3000;
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'CHANGE_THIS_SECRET_BEFORE_DEPLOY';
const DB_PATH      = process.env.DB_PATH      || path.join(__dirname, 'licenses.db');

// ── Database ──────────────────────────────────────────────────────────────────
const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS keys (
    key         TEXT PRIMARY KEY,
    label       TEXT,
    hwid        TEXT,
    activated   INTEGER DEFAULT 0,
    revoked     INTEGER DEFAULT 0,
    activatedAt TEXT,
    revokedAt   TEXT,
    createdAt   TEXT DEFAULT (datetime('now')),
    note        TEXT
  );

  CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    key       TEXT,
    event     TEXT,
    hwid      TEXT,
    ip        TEXT,
    ts        TEXT DEFAULT (datetime('now'))
  );
`);

// ── Helpers ───────────────────────────────────────────────────────────────────

function generateKey() {
  // Format: QF-XXXX-XXXX-XXXX-XXXX (hex segments)
  const seg = () => crypto.randomBytes(2).toString('hex').toUpperCase();
  return `QF-${seg()}${seg()}-${seg()}${seg()}-${seg()}${seg()}-${seg()}${seg()}`;
}

function logEvent(key, event, hwid, ip) {
  db.prepare('INSERT INTO events (key, event, hwid, ip) VALUES (?,?,?,?)').run(key, event, hwid || '', ip || '');
}

function requireAdmin(req, res, next) {
  const secret = req.headers['x-admin-secret'];
  if (!secret || secret !== ADMIN_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

function getClientIp(req) {
  return req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
}

// ── App ───────────────────────────────────────────────────────────────────────
const app = express();
app.use(cors());
app.use(express.json());

// Serve admin dashboard as static files
app.use('/admin-ui', express.static(path.join(__dirname, '../../admin')));

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', ts: new Date().toISOString() });
});

// ── Activate ──────────────────────────────────────────────────────────────────
// Called the first time someone enters a key on a new machine.
app.post('/activate', (req, res) => {
  const { key, hwid } = req.body;
  const ip = getClientIp(req);

  if (!key || !hwid) return res.status(400).json({ valid: false, error: 'Missing key or hwid' });

  const row = db.prepare('SELECT * FROM keys WHERE key = ?').get(key);

  if (!row)          return res.json({ valid: false, error: 'Key not found' });
  if (row.revoked)   return res.json({ valid: false, error: 'Key has been revoked' });

  // Already activated on a different device
  if (row.activated && row.hwid !== hwid) {
    logEvent(key, 'ACTIVATE_REJECTED_WRONG_DEVICE', hwid, ip);
    return res.json({ valid: false, error: 'Key already activated on another device' });
  }

  // First activation or same device re-activating
  if (!row.activated) {
    db.prepare('UPDATE keys SET activated = 1, hwid = ?, activatedAt = datetime(\'now\') WHERE key = ?').run(hwid, key);
    logEvent(key, 'ACTIVATED', hwid, ip);
  } else {
    logEvent(key, 'REACTIVATED', hwid, ip);
  }

  return res.json({ valid: true, message: 'Activated', label: row.label || '' });
});

// ── Validate ──────────────────────────────────────────────────────────────────
// Called on every app launch to confirm key is still valid.
app.post('/validate', (req, res) => {
  const { key, hwid } = req.body;
  const ip = getClientIp(req);

  if (!key || !hwid) return res.status(400).json({ valid: false, error: 'Missing key or hwid' });

  const row = db.prepare('SELECT * FROM keys WHERE key = ?').get(key);

  if (!row)               return res.json({ valid: false, error: 'Key not found' });
  if (row.revoked)        return res.json({ valid: false, error: 'Key revoked' });
  if (!row.activated)     return res.json({ valid: false, error: 'Key not yet activated' });
  if (row.hwid !== hwid)  return res.json({ valid: false, error: 'Key bound to a different device' });

  logEvent(key, 'VALIDATED', hwid, ip);
  return res.json({ valid: true, label: row.label || '' });
});

// ── Admin: Generate keys ──────────────────────────────────────────────────────
app.post('/admin/generate', requireAdmin, (req, res) => {
  const { count = 1, label = '', note = '' } = req.body;
  const n = Math.min(parseInt(count) || 1, 100); // max 100 at once

  const generated = [];
  const insert = db.prepare('INSERT INTO keys (key, label, note) VALUES (?, ?, ?)');

  for (let i = 0; i < n; i++) {
    const key = generateKey();
    insert.run(key, label, note);
    generated.push(key);
  }

  return res.json({ generated, count: generated.length });
});

// ── Admin: Revoke key ─────────────────────────────────────────────────────────
app.post('/admin/revoke', requireAdmin, (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'Missing key' });

  const row = db.prepare('SELECT * FROM keys WHERE key = ?').get(key);
  if (!row) return res.status(404).json({ error: 'Key not found' });

  db.prepare('UPDATE keys SET revoked = 1, revokedAt = datetime(\'now\') WHERE key = ?').run(key);
  logEvent(key, 'REVOKED', row.hwid, '');
  return res.json({ success: true, key });
});

// ── Admin: Unrevoke key ───────────────────────────────────────────────────────
app.post('/admin/unrevoke', requireAdmin, (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'Missing key' });
  db.prepare('UPDATE keys SET revoked = 0, revokedAt = NULL WHERE key = ?').run(key);
  logEvent(key, 'UNREVOKED', '', '');
  return res.json({ success: true, key });
});

// ── Admin: List keys ──────────────────────────────────────────────────────────
app.get('/admin/keys', requireAdmin, (req, res) => {
  const keys = db.prepare('SELECT * FROM keys ORDER BY createdAt DESC').all();
  const events = db.prepare('SELECT * FROM events ORDER BY ts DESC LIMIT 200').all();
  const stats = {
    total: keys.length,
    activated: keys.filter(k => k.activated).length,
    revoked: keys.filter(k => k.revoked).length,
    unused: keys.filter(k => !k.activated && !k.revoked).length,
  };
  return res.json({ keys, events, stats });
});

// ── Admin: Delete key ─────────────────────────────────────────────────────────
app.post('/admin/delete', requireAdmin, (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'Missing key' });
  db.prepare('DELETE FROM keys WHERE key = ?').run(key);
  db.prepare('DELETE FROM events WHERE key = ?').run(key);
  return res.json({ success: true });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Quickfire License Server running on port ${PORT}`);
  console.log(`Admin dashboard: http://localhost:${PORT}/admin-ui`);
  console.log(`Admin secret: ${ADMIN_SECRET === 'CHANGE_THIS_SECRET_BEFORE_DEPLOY' ? '⚠️  USING DEFAULT — SET ADMIN_SECRET ENV VAR' : '✓ set via environment'}`);
});

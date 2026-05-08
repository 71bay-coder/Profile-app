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

// Serve admin dashboard inline — no filesystem path dependency
app.get('/admin-ui', (req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Quickfire — License Admin</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@2.44.0/tabler-icons.min.css">
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --mono:'IBM Plex Mono',monospace;--sans:'IBM Plex Sans',sans-serif;
  --bg:#0e0e0d;--bg2:#161614;--bg3:#1e1e1c;--bg4:#262624;
  --ink:#e8e6e0;--ink2:#9a9890;--ink3:#5a5856;
  --border:rgba(255,255,255,0.07);--border2:rgba(255,255,255,0.14);
  --accent:#1D9E75;--danger:#E24B4A;--warn:#EF9F27;--rad:8px;--radlg:12px;
}
html,body{min-height:100vh;background:var(--bg3);font-family:var(--sans);color:var(--ink);font-size:14px}
.shell{max-width:1100px;margin:0 auto;padding:28px 20px 60px}

/* Header */
.topbar{display:flex;align-items:center;justify-content:space-between;padding:14px 20px;background:var(--bg2);border:0.5px solid var(--border2);border-radius:var(--radlg);margin-bottom:20px}
.logo{display:flex;align-items:center;gap:10px}
.logo-icon{width:34px;height:34px;background:var(--accent);border-radius:6px;display:flex;align-items:center;justify-content:center;color:#fff;font-size:17px}
.logo-text{font-family:var(--mono);font-size:14px;font-weight:600;letter-spacing:0.06em}
.logo-sub{font-size:11px;color:var(--ink3);font-family:var(--mono)}
.auth-row{display:flex;gap:8px;align-items:center}
.secret-input{font-family:var(--mono);font-size:12px;border:0.5px solid var(--border2);border-radius:var(--rad);padding:7px 12px;background:var(--bg3);color:var(--ink);width:260px}
.secret-input:focus{outline:2px solid var(--accent);outline-offset:1px}

/* Stats */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
.stat{background:var(--bg2);border:0.5px solid var(--border);border-radius:var(--radlg);padding:14px 16px}
.stat-val{font-family:var(--mono);font-size:26px;font-weight:600;color:var(--ink);margin-bottom:4px}
.stat-val.green{color:var(--accent)}
.stat-val.red{color:var(--danger)}
.stat-val.warn{color:var(--warn)}
.stat-label{font-size:11px;color:var(--ink3)}

/* Cards */
.card{background:var(--bg2);border:0.5px solid var(--border);border-radius:var(--radlg);padding:18px 20px;margin-bottom:16px}
.card-title{font-family:var(--mono);font-size:10px;font-weight:600;color:var(--ink3);letter-spacing:0.12em;text-transform:uppercase;margin-bottom:14px;display:flex;align-items:center;justify-content:space-between}

/* Generate form */
.gen-row{display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap}
.field{display:flex;flex-direction:column;gap:5px}
.field label{font-size:11px;color:var(--ink3);font-family:var(--mono)}
.fi{font-family:var(--mono);font-size:12px;border:0.5px solid var(--border2);border-radius:var(--rad);padding:7px 10px;background:var(--bg3);color:var(--ink)}
.fi:focus{outline:2px solid var(--accent);outline-offset:1px}
.fi.short{width:80px}
.fi.med{width:200px}

/* Buttons */
.btn{font-family:var(--mono);font-size:11px;font-weight:600;padding:8px 14px;border-radius:var(--rad);border:none;cursor:pointer;transition:0.12s;letter-spacing:0.05em;display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.btn-primary{background:var(--accent);color:#fff}.btn-primary:hover{background:#17875f}
.btn-danger{background:var(--danger);color:#fff}.btn-danger:hover{background:#c43a39}
.btn-outline{background:var(--bg3);color:var(--ink2);border:0.5px solid var(--border2)}.btn-outline:hover{background:var(--bg4);color:var(--ink)}
.btn-sm{padding:5px 10px;font-size:10px}
.btn-warn{background:var(--warn);color:#000}.btn-warn:hover{filter:brightness(0.9)}

/* Generated keys display */
.keys-output{background:var(--bg3);border-radius:var(--rad);padding:14px;font-family:var(--mono);font-size:12px;color:var(--accent);margin-top:12px;line-height:1.8;border:0.5px solid var(--border);display:none;word-break:break-all}

/* Keys table */
.keys-table{width:100%;border-collapse:collapse;font-size:12px}
.keys-table th{font-family:var(--mono);font-size:10px;font-weight:600;color:var(--ink3);letter-spacing:0.1em;text-transform:uppercase;padding:8px 12px;text-align:left;border-bottom:0.5px solid var(--border2)}
.keys-table td{padding:9px 12px;border-bottom:0.5px solid var(--border);font-family:var(--mono);font-size:11px;color:var(--ink2);vertical-align:middle}
.keys-table tr:last-child td{border-bottom:none}
.keys-table tr:hover td{background:var(--bg3)}
.key-cell{color:var(--ink);letter-spacing:0.03em}
.status-pill{display:inline-block;font-family:var(--mono);font-size:9px;font-weight:600;padding:2px 8px;border-radius:20px}
.pill-unused{background:var(--bg4);color:var(--ink3)}
.pill-active{background:#1a3d2e;color:#5DCAA5}
.pill-revoked{background:#3d1a1a;color:#f09595}

/* Events */
.events-list{max-height:240px;overflow-y:auto;display:flex;flex-direction:column;gap:3px}
.event-row{display:flex;gap:10px;padding:5px 10px;border-radius:var(--rad);background:var(--bg3);font-family:var(--mono);font-size:10px}
.ev-time{color:var(--ink3);flex-shrink:0}
.ev-key{color:var(--ink2);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ev-type{font-weight:600}
.ev-type.ACTIVATED{color:#5DCAA5}
.ev-type.VALIDATED{color:var(--ink3)}
.ev-type.REVOKED,.ev-type.ACTIVATE_REJECTED_WRONG_DEVICE{color:#f09595}
.ev-type.REACTIVATED{color:var(--warn)}
.ev-type.UNREVOKED{color:var(--accent)}

/* Search */
.search-row{display:flex;gap:10px;margin-bottom:12px;align-items:center}
.search-input{flex:1;font-family:var(--mono);font-size:12px;border:0.5px solid var(--border2);border-radius:var(--rad);padding:7px 12px;background:var(--bg3);color:var(--ink)}
.search-input:focus{outline:2px solid var(--accent);outline-offset:1px}

/* Copy btn */
.copy-btn{background:none;border:none;color:var(--ink3);cursor:pointer;font-size:13px;padding:2px 4px;border-radius:4px}
.copy-btn:hover{color:var(--accent)}

/* Toast */
.toast{position:fixed;bottom:24px;right:24px;padding:11px 18px;border-radius:var(--radlg);font-family:var(--mono);font-size:11px;font-weight:600;border:0.5px solid;z-index:999;display:none;max-width:340px}
.toast.show{display:block;animation:si 0.2s ease}
.toast-success{background:#0d2a1e;color:#5DCAA5;border-color:#1D9E75}
.toast-error{background:#2a0d0d;color:#f09595;border-color:var(--danger)}
.toast-warn{background:#2a1a00;color:var(--warn);border-color:var(--warn)}
@keyframes si{from{transform:translateY(8px);opacity:0}to{transform:translateY(0);opacity:1}}

.filter-btns{display:flex;gap:6px}
.filter-btn{font-family:var(--mono);font-size:10px;font-weight:600;padding:5px 12px;border-radius:20px;border:0.5px solid var(--border2);background:var(--bg3);color:var(--ink3);cursor:pointer;transition:0.12s}
.filter-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.filter-btn:hover:not(.active){background:var(--bg4);color:var(--ink)}
.hwid-cell{max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--ink3)}
.note-cell{max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
</style>
</head>
<body>
<div class="shell">

  <div class="topbar">
    <div class="logo">
      <div class="logo-icon"><i class="ti ti-bolt"></i></div>
      <div><div class="logo-text">QUICKFIRE</div><div class="logo-sub">license admin dashboard</div></div>
    </div>
    <div class="auth-row">
      <input class="secret-input" id="secret-input" type="password" placeholder="Admin secret key..." autocomplete="off">
      <button class="btn btn-primary" onclick="loadAll()"><i class="ti ti-refresh"></i> Load</button>
    </div>
  </div>

  <!-- Stats -->
  <div class="stats">
    <div class="stat"><div class="stat-val" id="st-total">—</div><div class="stat-label">Total keys</div></div>
    <div class="stat"><div class="stat-val green" id="st-active">—</div><div class="stat-label">Activated</div></div>
    <div class="stat"><div class="stat-val warn" id="st-unused">—</div><div class="stat-label">Unused</div></div>
    <div class="stat"><div class="stat-val red" id="st-revoked">—</div><div class="stat-label">Revoked</div></div>
  </div>

  <!-- Generate -->
  <div class="card">
    <div class="card-title">Generate new keys</div>
    <div class="gen-row">
      <div class="field"><label>Count</label><input class="fi short" id="gen-count" type="number" value="1" min="1" max="100"></div>
      <div class="field"><label>Label (optional)</label><input class="fi med" id="gen-label" placeholder="e.g. Beta user, Discord giveaway"></div>
      <div class="field"><label>Note (optional)</label><input class="fi med" id="gen-note" placeholder="Internal note"></div>
      <button class="btn btn-primary" onclick="generateKeys()" style="align-self:flex-end"><i class="ti ti-key"></i> Generate</button>
    </div>
    <div class="keys-output" id="keys-output"></div>
  </div>

  <!-- Keys table -->
  <div class="card">
    <div class="card-title">
      All keys
      <div style="display:flex;gap:10px;align-items:center">
        <button class="btn btn-outline btn-sm" onclick="loadAll()"><i class="ti ti-refresh"></i> Refresh</button>
        <button class="btn btn-outline btn-sm" onclick="exportCSV()"><i class="ti ti-download"></i> Export CSV</button>
      </div>
    </div>
    <div class="search-row">
      <input class="search-input" id="search-input" placeholder="Search by key, label, hwid, note..." oninput="renderTable()">
      <div class="filter-btns">
        <button class="filter-btn active" data-filter="all" onclick="setFilter('all',this)">All</button>
        <button class="filter-btn" data-filter="unused" onclick="setFilter('unused',this)">Unused</button>
        <button class="filter-btn" data-filter="active" onclick="setFilter('active',this)">Active</button>
        <button class="filter-btn" data-filter="revoked" onclick="setFilter('revoked',this)">Revoked</button>
      </div>
    </div>
    <div style="overflow-x:auto">
      <table class="keys-table">
        <thead>
          <tr>
            <th>Key</th><th>Label</th><th>Status</th><th>Device (HWID)</th>
            <th>Activated</th><th>Created</th><th>Note</th><th>Actions</th>
          </tr>
        </thead>
        <tbody id="keys-tbody"></tbody>
      </table>
    </div>
    <div id="no-keys" style="display:none;text-align:center;padding:24px;color:var(--ink3);font-family:var(--mono);font-size:12px">No keys found</div>
  </div>

  <!-- Events -->
  <div class="card">
    <div class="card-title">Recent events</div>
    <div class="events-list" id="events-list"></div>
  </div>

</div>

<div class="toast" id="toast"></div>

<script>
let _keys = [];
let _events = [];
let _filter = 'all';
let _serverUrl = window.location.origin; // Same origin as the server

function getSecret() { return document.getElementById('secret-input').value.trim(); }

async function loadAll() {
  const secret = getSecret();
  if (!secret) { toast('Enter your admin secret first', 'error'); return; }
  try {
    const res = await fetch(_serverUrl + '/admin/keys', { headers: { 'X-Admin-Secret': secret } });
    if (res.status === 401) { toast('Wrong admin secret', 'error'); return; }
    const data = await res.json();
    _keys = data.keys || [];
    _events = data.events || [];
    updateStats(data.stats || {});
    renderTable();
    renderEvents();
    toast('Loaded ' + _keys.length + ' keys', 'success');
  } catch(e) {
    toast('Could not connect to server: ' + e.message, 'error');
  }
}

async function generateKeys() {
  const secret = getSecret();
  if (!secret) { toast('Enter your admin secret first', 'error'); return; }
  const count = parseInt(document.getElementById('gen-count').value) || 1;
  const label = document.getElementById('gen-label').value.trim();
  const note  = document.getElementById('gen-note').value.trim();
  try {
    const res = await fetch(_serverUrl + '/admin/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Admin-Secret': secret },
      body: JSON.stringify({ count, label, note })
    });
    const data = await res.json();
    const out = document.getElementById('keys-output');
    out.style.display = 'block';
    out.innerHTML = data.generated.map(k =>
      '<div style="display:flex;align-items:center;gap:8px">' + k +
      ' <button class="copy-btn" onclick="copyKey(\'' + k + '\')" title="Copy"><i class="ti ti-copy"></i></button></div>'
    ).join('');
    toast('Generated ' + data.count + ' key(s)', 'success');
    loadAll();
  } catch(e) { toast('Error: ' + e.message, 'error'); }
}

async function revokeKey(key) {
  if (!confirm('Revoke key ' + key + '? The user will lose access immediately.')) return;
  const secret = getSecret();
  const res = await fetch(_serverUrl + '/admin/revoke', {
    method: 'POST', headers: { 'Content-Type':'application/json','X-Admin-Secret':secret },
    body: JSON.stringify({ key })
  });
  const data = await res.json();
  if (data.success) { toast('Key revoked', 'warn'); loadAll(); }
  else toast('Error: ' + data.error, 'error');
}

async function unrevokeKey(key) {
  const secret = getSecret();
  const res = await fetch(_serverUrl + '/admin/unrevoke', {
    method: 'POST', headers: { 'Content-Type':'application/json','X-Admin-Secret':secret },
    body: JSON.stringify({ key })
  });
  const data = await res.json();
  if (data.success) { toast('Key restored', 'success'); loadAll(); }
  else toast('Error: ' + data.error, 'error');
}

async function deleteKey(key) {
  if (!confirm('Permanently delete ' + key + '? This cannot be undone.')) return;
  const secret = getSecret();
  const res = await fetch(_serverUrl + '/admin/delete', {
    method: 'POST', headers: { 'Content-Type':'application/json','X-Admin-Secret':secret },
    body: JSON.stringify({ key })
  });
  const data = await res.json();
  if (data.success) { toast('Key deleted', 'warn'); loadAll(); }
  else toast('Error: ' + data.error, 'error');
}

function copyKey(key) {
  navigator.clipboard.writeText(key).then(() => toast('Copied: ' + key, 'success'));
}

function setFilter(f, el) {
  _filter = f;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  el.classList.add('active');
  renderTable();
}

function updateStats(s) {
  document.getElementById('st-total').textContent   = s.total   ?? '—';
  document.getElementById('st-active').textContent  = s.activated ?? '—';
  document.getElementById('st-unused').textContent  = s.unused  ?? '—';
  document.getElementById('st-revoked').textContent = s.revoked ?? '—';
}

function renderTable() {
  const search = (document.getElementById('search-input').value || '').toLowerCase();
  let filtered = _keys.filter(k => {
    if (_filter === 'unused')  return !k.activated && !k.revoked;
    if (_filter === 'active')  return k.activated && !k.revoked;
    if (_filter === 'revoked') return !!k.revoked;
    return true;
  }).filter(k => {
    if (!search) return true;
    return (k.key+k.label+k.hwid+k.note).toLowerCase().includes(search);
  });

  const tbody = document.getElementById('keys-tbody');
  const noKeys = document.getElementById('no-keys');
  tbody.innerHTML = '';
  noKeys.style.display = filtered.length ? 'none' : 'block';

  filtered.forEach(k => {
    const status = k.revoked ? 'revoked' : k.activated ? 'active' : 'unused';
    const pillCls = { revoked:'pill-revoked', active:'pill-active', unused:'pill-unused' }[status];
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="key-cell">\${k.key} <button class="copy-btn" onclick="copyKey('\${k.key}')" title="Copy"><i class="ti ti-copy"></i></button></td>
      <td>\${k.label || '<span style="color:var(--ink3)">—</span>'}</td>
      <td><span class="status-pill \${pillCls}">\${status.toUpperCase()}</span></td>
      <td class="hwid-cell" title="\${k.hwid||''}">\${k.hwid ? k.hwid.slice(0,20)+'...' : '<span style="color:var(--ink3)">—</span>'}</td>
      <td>\${k.activatedAt ? k.activatedAt.slice(0,16) : '<span style="color:var(--ink3)">—</span>'}</td>
      <td>\${k.createdAt ? k.createdAt.slice(0,16) : '—'}</td>
      <td class="note-cell" title="\${k.note||''}">\${k.note || '<span style="color:var(--ink3)">—</span>'}</td>
      <td style="display:flex;gap:5px;flex-wrap:wrap">
        \${!k.revoked ? `<button class="btn btn-danger btn-sm" onclick="revokeKey('\${k.key}')"><i class="ti ti-ban"></i> Revoke</button>` : `<button class="btn btn-warn btn-sm" onclick="unrevokeKey('\${k.key}')"><i class="ti ti-refresh"></i> Restore</button>`}
        <button class="btn btn-outline btn-sm" onclick="deleteKey('\${k.key}')"><i class="ti ti-trash"></i></button>
      </td>`;
    tbody.appendChild(tr);
  });
}

function renderEvents() {
  const el = document.getElementById('events-list');
  el.innerHTML = '';
  _events.slice(0, 80).forEach(e => {
    const div = document.createElement('div');
    div.className = 'event-row';
    div.innerHTML = `<span class="ev-time">\${(e.ts||'').slice(0,16)}</span><span class="ev-key">\${e.key}</span><span class="ev-type \${e.event}">\${e.event}</span>\${e.hwid ? '<span style="color:var(--ink3);font-size:9px">'+e.hwid.slice(0,12)+'</span>' : ''}`;
    el.appendChild(div);
  });
}

function exportCSV() {
  if (!_keys.length) { toast('No keys to export','warn'); return; }
  const header = 'key,label,status,hwid,activatedAt,createdAt,note';
  const rows = _keys.map(k => [k.key, k.label||'', k.revoked?'revoked':k.activated?'active':'unused', k.hwid||'', k.activatedAt||'', k.createdAt||'', (k.note||'').replace(/,/g,';')].join(','));
  const csv = [header, ...rows].join('\n');
  const a = document.createElement('a');
  a.href = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
  a.download = 'quickfire-keys-' + new Date().toISOString().slice(0,10) + '.csv';
  a.click();
  toast('Exported ' + _keys.length + ' keys', 'success');
}

function toast(msg, type='') {
  const el = document.getElementById('toast');
  el.textContent = msg; el.className = 'toast show toast-'+(type||'warn');
  clearTimeout(el._t); el._t = setTimeout(()=>el.classList.remove('show'), 2800);
}
</script>
</body>
</html>
`);
});

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

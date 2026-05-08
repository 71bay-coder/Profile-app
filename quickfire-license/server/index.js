const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');

const PORT = process.env.PORT || 3000;
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'CHANGE_THIS';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'licenses.db');

const db = new Database(DB_PATH);
db.exec("CREATE TABLE IF NOT EXISTS keys (key TEXT PRIMARY KEY, label TEXT, hwid TEXT, activated INTEGER DEFAULT 0, revoked INTEGER DEFAULT 0, activatedAt TEXT, revokedAt TEXT, createdAt TEXT DEFAULT (datetime('now')), note TEXT)");
db.exec("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT, event TEXT, hwid TEXT, ip TEXT, ts TEXT DEFAULT (datetime('now')))");

function makeKey() {
  var s = function() { return crypto.randomBytes(2).toString('hex').toUpperCase(); };
  return 'QF-' + s() + s() + '-' + s() + s() + '-' + s() + s() + '-' + s() + s();
}

function logEvent(key, event, hwid, ip) {
  db.prepare('INSERT INTO events (key,event,hwid,ip) VALUES (?,?,?,?)').run(key, event, hwid||'', ip||'');
}

function adminOnly(req, res, next) {
  if (req.headers['x-admin-secret'] !== ADMIN_SECRET) return res.status(401).json({error:'Unauthorized'});
  next();
}

var app = express();
app.use(cors());
app.use(express.json());

app.get('/health', function(req, res) {
  res.json({status:'ok', ts: new Date().toISOString()});
});

app.get('/admin-ui', function(req, res) {
  res.setHeader('Content-Type', 'text/html');
  res.end(ADMIN_HTML);
});

app.post('/activate', function(req, res) {
  var key = req.body.key, hwid = req.body.hwid;
  var ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
  if (!key || !hwid) return res.json({valid:false, error:'Missing key or hwid'});
  var row = db.prepare('SELECT * FROM keys WHERE key=?').get(key);
  if (!row) return res.json({valid:false, error:'Key not found'});
  if (row.revoked) return res.json({valid:false, error:'Key revoked'});
  if (row.activated && row.hwid !== hwid) { logEvent(key,'REJECTED',hwid,ip); return res.json({valid:false, error:'Key used on another device'}); }
  if (!row.activated) { db.prepare("UPDATE keys SET activated=1,hwid=?,activatedAt=datetime('now') WHERE key=?").run(hwid,key); logEvent(key,'ACTIVATED',hwid,ip); }
  else logEvent(key,'REACTIVATED',hwid,ip);
  res.json({valid:true, label:row.label||''});
});

app.post('/validate', function(req, res) {
  var key = req.body.key, hwid = req.body.hwid;
  var ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
  if (!key || !hwid) return res.json({valid:false, error:'Missing'});
  var row = db.prepare('SELECT * FROM keys WHERE key=?').get(key);
  if (!row || row.revoked || !row.activated || row.hwid !== hwid) return res.json({valid:false, error:'Invalid'});
  logEvent(key,'VALIDATED',hwid,ip);
  res.json({valid:true, label:row.label||''});
});

app.post('/admin/generate', adminOnly, function(req, res) {
  var count = Math.min(parseInt(req.body.count)||1, 100);
  var label = req.body.label||'', note = req.body.note||'';
  var ins = db.prepare('INSERT INTO keys (key,label,note) VALUES (?,?,?)');
  var out = [];
  for (var i=0; i<count; i++) { var k=makeKey(); ins.run(k,label,note); out.push(k); }
  res.json({generated:out, count:out.length});
});

app.post('/admin/revoke', adminOnly, function(req, res) {
  var key = req.body.key;
  if (!key) return res.status(400).json({error:'Missing key'});
  db.prepare("UPDATE keys SET revoked=1,revokedAt=datetime('now') WHERE key=?").run(key);
  logEvent(key,'REVOKED','','');
  res.json({success:true});
});

app.post('/admin/unrevoke', adminOnly, function(req, res) {
  var key = req.body.key;
  db.prepare('UPDATE keys SET revoked=0,revokedAt=NULL WHERE key=?').run(key);
  logEvent(key,'UNREVOKED','','');
  res.json({success:true});
});

app.post('/admin/delete', adminOnly, function(req, res) {
  var key = req.body.key;
  db.prepare('DELETE FROM keys WHERE key=?').run(key);
  db.prepare('DELETE FROM events WHERE key=?').run(key);
  res.json({success:true});
});

app.get('/admin/keys', adminOnly, function(req, res) {
  var keys = db.prepare('SELECT * FROM keys ORDER BY createdAt DESC').all();
  var events = db.prepare('SELECT * FROM events ORDER BY ts DESC LIMIT 200').all();
  res.json({
    keys: keys,
    events: events,
    stats: {
      total: keys.length,
      activated: keys.filter(function(k){return k.activated;}).length,
      revoked: keys.filter(function(k){return k.revoked;}).length,
      unused: keys.filter(function(k){return !k.activated && !k.revoked;}).length
    }
  });
});

app.listen(PORT, function() {
  console.log('Quickfire License Server running on port ' + PORT);
});

var ADMIN_HTML = [
'<!DOCTYPE html><html><head><meta charset="UTF-8">',
'<title>Quickfire Admin</title>',
'<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@2.44.0/tabler-icons.min.css">',
'<style>',
'*{box-sizing:border-box;margin:0;padding:0}',
'body{background:#1e1e1c;color:#e8e6e0;font-family:sans-serif;font-size:14px;padding:20px}',
'.top{display:flex;align-items:center;justify-content:space-between;background:#161614;border:1px solid rgba(255,255,255,0.1);border-radius:10px;padding:14px 20px;margin-bottom:20px}',
'.logo{font-family:monospace;font-size:16px;font-weight:600;color:#1D9E75}',
'.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}',
'.stat{background:#161614;border:1px solid rgba(255,255,255,0.1);border-radius:10px;padding:14px}',
'.sv{font-family:monospace;font-size:24px;font-weight:600;margin-bottom:4px}',
'.sl{font-size:11px;color:#9a9890}',
'.green{color:#1D9E75}.red{color:#E24B4A}.warn{color:#EF9F27}',
'.card{background:#161614;border:1px solid rgba(255,255,255,0.1);border-radius:10px;padding:18px;margin-bottom:16px}',
'.ct{font-family:monospace;font-size:10px;font-weight:600;color:#9a9890;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:14px}',
'.row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}',
'.field{display:flex;flex-direction:column;gap:5px}',
'.fl{font-size:11px;color:#9a9890;font-family:monospace}',
'input{font-family:monospace;font-size:12px;border:1px solid rgba(255,255,255,0.15);border-radius:6px;padding:7px 10px;background:#1e1e1c;color:#e8e6e0}',
'.btn{font-family:monospace;font-size:11px;font-weight:600;padding:8px 14px;border-radius:6px;border:none;cursor:pointer;display:inline-flex;align-items:center;gap:6px}',
'.bp{background:#1D9E75;color:#fff}.bp:hover{background:#17875f}',
'.bd{background:#E24B4A;color:#fff}',
'.bo{background:#1e1e1c;color:#9a9890;border:1px solid rgba(255,255,255,0.15)}',
'.bw{background:#EF9F27;color:#000}',
'.bs{padding:5px 10px;font-size:10px}',
'.out{background:#1e1e1c;border:1px solid rgba(255,255,255,0.1);border-radius:6px;padding:14px;font-family:monospace;font-size:12px;color:#1D9E75;margin-top:12px;line-height:1.8;display:none;word-break:break-all}',
'.srow{display:flex;gap:10px;margin-bottom:12px}',
'.si{flex:1;font-family:monospace;font-size:12px;border:1px solid rgba(255,255,255,0.15);border-radius:6px;padding:7px 12px;background:#1e1e1c;color:#e8e6e0}',
'.fbs{display:flex;gap:6px}',
'.fb{font-family:monospace;font-size:10px;font-weight:600;padding:5px 12px;border-radius:20px;border:1px solid rgba(255,255,255,0.15);background:#1e1e1c;color:#9a9890;cursor:pointer}',
'.fb.a{background:#1D9E75;color:#fff;border-color:#1D9E75}',
'table{width:100%;border-collapse:collapse;font-size:12px}',
'th{font-family:monospace;font-size:10px;font-weight:600;color:#9a9890;letter-spacing:0.1em;text-transform:uppercase;padding:8px 12px;text-align:left;border-bottom:1px solid rgba(255,255,255,0.1)}',
'td{padding:9px 12px;border-bottom:1px solid rgba(255,255,255,0.07);font-family:monospace;font-size:11px;color:#9a9890;vertical-align:middle}',
'tr:hover td{background:#262624}',
'.pill{display:inline-block;font-family:monospace;font-size:9px;font-weight:600;padding:2px 8px;border-radius:20px}',
'.pu{background:#262624;color:#9a9890}.pa{background:#1a3d2e;color:#5DCAA5}.pr{background:#3d1a1a;color:#f09595}',
'.ev{max-height:200px;overflow-y:auto;display:flex;flex-direction:column;gap:3px}',
'.er{display:flex;gap:10px;padding:5px 10px;border-radius:4px;background:#1e1e1c;font-family:monospace;font-size:10px}',
'.et{color:#9a9890;flex-shrink:0}.ek{color:#9a9890;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
'.cb{background:none;border:none;color:#9a9890;cursor:pointer;font-size:13px;padding:2px 4px}',
'.toast{position:fixed;bottom:24px;right:24px;padding:11px 18px;border-radius:10px;font-family:monospace;font-size:11px;font-weight:600;border:1px solid;z-index:999;display:none}',
'.ts{display:block;animation:si 0.2s ease}',
'.tg{background:#0d2a1e;color:#5DCAA5;border-color:#1D9E75}',
'.te{background:#2a0d0d;color:#f09595;border-color:#E24B4A}',
'.tw{background:#2a1a00;color:#EF9F27;border-color:#EF9F27}',
'@keyframes si{from{transform:translateY(8px);opacity:0}to{transform:translateY(0);opacity:1}}',
'</style></head><body>',
'<div class="top">',
'<div class="logo">⚡ QUICKFIRE ADMIN</div>',
'<div style="display:flex;gap:8px;align-items:center">',
'<input id="sec" type="password" placeholder="Admin secret..." autocomplete="off" style="width:220px">',
'<button class="btn bp" onclick="load()">Load</button>',
'</div></div>',
'<div class="stats">',
'<div class="stat"><div class="sv" id="t0">-</div><div class="sl">Total keys</div></div>',
'<div class="stat"><div class="sv green" id="t1">-</div><div class="sl">Activated</div></div>',
'<div class="stat"><div class="sv warn" id="t2">-</div><div class="sl">Unused</div></div>',
'<div class="stat"><div class="sv red" id="t3">-</div><div class="sl">Revoked</div></div>',
'</div>',
'<div class="card">',
'<div class="ct">Generate keys</div>',
'<div class="row">',
'<div class="field"><span class="fl">Count</span><input id="gc" type="number" value="1" min="1" max="100" style="width:70px"></div>',
'<div class="field"><span class="fl">Label</span><input id="gl" placeholder="e.g. Beta user" style="width:180px"></div>',
'<div class="field"><span class="fl">Note</span><input id="gn" placeholder="Internal note" style="width:180px"></div>',
'<button class="btn bp" onclick="gen()" style="align-self:flex-end">Generate</button>',
'</div>',
'<div class="out" id="gout"></div>',
'</div>',
'<div class="card">',
'<div class="ct" style="display:flex;justify-content:space-between">Keys <div style="display:flex;gap:8px"><button class="btn bo bs" onclick="load()">Refresh</button><button class="btn bo bs" onclick="csv()">Export CSV</button></div></div>',
'<div class="srow">',
'<input class="si" id="srch" placeholder="Search..." oninput="render()">',
'<div class="fbs">',
'<button class="fb a" onclick="setF(\'all\',this)">All</button>',
'<button class="fb" onclick="setF(\'unused\',this)">Unused</button>',
'<button class="fb" onclick="setF(\'active\',this)">Active</button>',
'<button class="fb" onclick="setF(\'revoked\',this)">Revoked</button>',
'</div></div>',
'<div style="overflow-x:auto"><table>',
'<thead><tr><th>Key</th><th>Label</th><th>Status</th><th>Device</th><th>Activated</th><th>Created</th><th>Actions</th></tr></thead>',
'<tbody id="tbody"></tbody>',
'</table></div>',
'<div id="nok" style="display:none;text-align:center;padding:20px;color:#9a9890;font-family:monospace;font-size:12px">No keys found</div>',
'</div>',
'<div class="card"><div class="ct">Recent events</div><div class="ev" id="evl"></div></div>',
'<div class="toast" id="toast"></div>',
'<script>',
'var K=[],E=[],F="all",U=location.origin;',
'function sec(){return document.getElementById("sec").value.trim();}',
'function load(){',
'var s=sec();if(!s){toast("Enter admin secret","e");return;}',
'fetch(U+"/admin/keys",{headers:{"X-Admin-Secret":s}})',
'.then(function(r){if(r.status===401){toast("Wrong secret","e");return null;}return r.json();})',
'.then(function(d){if(!d)return;K=d.keys||[];E=d.events||[];',
'document.getElementById("t0").textContent=d.stats.total||0;',
'document.getElementById("t1").textContent=d.stats.activated||0;',
'document.getElementById("t2").textContent=d.stats.unused||0;',
'document.getElementById("t3").textContent=d.stats.revoked||0;',
'render();renderEv();toast("Loaded "+K.length+" keys","g");',
'}).catch(function(e){toast("Error: "+e.message,"e");});}',
'function gen(){',
'var s=sec();if(!s){toast("Enter secret","e");return;}',
'var c=parseInt(document.getElementById("gc").value)||1;',
'var l=document.getElementById("gl").value;',
'var n=document.getElementById("gn").value;',
'fetch(U+"/admin/generate",{method:"POST",headers:{"Content-Type":"application/json","X-Admin-Secret":s},body:JSON.stringify({count:c,label:l,note:n})})',
'.then(function(r){return r.json();})',
'.then(function(d){',
'var o=document.getElementById("gout");o.style.display="block";',
'o.innerHTML=d.generated.map(function(k){',
'return "<div style=\'display:flex;align-items:center;gap:8px\'>"+k+" <button class=\'cb\' onclick=\'copy(\\""+k+"\\")\'><i class=\'ti ti-copy\'></i></button></div>";',
'}).join("");',
'toast("Generated "+d.count+" key(s)","g");load();',
'});}',
'function revoke(k){',
'if(!confirm("Revoke "+k+"?"))return;var s=sec();',
'fetch(U+"/admin/revoke",{method:"POST",headers:{"Content-Type":"application/json","X-Admin-Secret":s},body:JSON.stringify({key:k})})',
'.then(function(r){return r.json();})',
'.then(function(d){if(d.success){toast("Revoked","w");load();}else toast(d.error,"e");});}',
'function unrevoke(k){var s=sec();',
'fetch(U+"/admin/unrevoke",{method:"POST",headers:{"Content-Type":"application/json","X-Admin-Secret":s},body:JSON.stringify({key:k})})',
'.then(function(r){return r.json();})',
'.then(function(){toast("Restored","g");load();});}',
'function del(k){',
'if(!confirm("Delete "+k+" permanently?"))return;var s=sec();',
'fetch(U+"/admin/delete",{method:"POST",headers:{"Content-Type":"application/json","X-Admin-Secret":s},body:JSON.stringify({key:k})})',
'.then(function(r){return r.json();})',
'.then(function(){toast("Deleted","w");load();});}',
'function copy(k){navigator.clipboard.writeText(k).then(function(){toast("Copied!","g");});}',
'function setF(f,el){F=f;document.querySelectorAll(".fb").forEach(function(b){b.classList.remove("a");});el.classList.add("a");render();}',
'function render(){',
'var q=(document.getElementById("srch").value||"").toLowerCase();',
'var filt=K.filter(function(k){',
'if(F==="unused")return !k.activated&&!k.revoked;',
'if(F==="active")return k.activated&&!k.revoked;',
'if(F==="revoked")return !!k.revoked;',
'return true;',
'}).filter(function(k){if(!q)return true;return (k.key+k.label+k.hwid+k.note).toLowerCase().indexOf(q)>=0;});',
'var tb=document.getElementById("tbody");',
'var nk=document.getElementById("nok");',
'tb.innerHTML="";',
'nk.style.display=filt.length?"none":"block";',
'filt.forEach(function(k){',
'var st=k.revoked?"revoked":k.activated?"active":"unused";',
'var pc={"revoked":"pr","active":"pa","unused":"pu"}[st];',
'var tr=document.createElement("tr");',
'tr.innerHTML="<td>"+k.key+" <button class=\'cb\' onclick=\'copy(\\""+k.key+"\\")\'><i class=\'ti ti-copy\'></i></button></td>"',
'+"<td>"+(k.label||"-")+"</td>"',
'+"<td><span class=\'pill "+pc+"\'>"+(st.toUpperCase())+"</span></td>"',
'+"<td style=\'max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap\'>"+(k.hwid?k.hwid.slice(0,16)+"...":"-")+"</td>"',
'+"<td>"+(k.activatedAt?k.activatedAt.slice(0,16):"-")+"</td>"',
'+"<td>"+(k.createdAt?k.createdAt.slice(0,16):"-")+"</td>"',
'+"<td style=\'display:flex;gap:5px\'>"',
'+(k.revoked',
'?"<button class=\'btn bw bs\' onclick=\'unrevoke(\\""+k.key+"\\")\'><i class=\'ti ti-refresh\'></i> Restore</button>"',
':"<button class=\'btn bd bs\' onclick=\'revoke(\\""+k.key+"\\")\'><i class=\'ti ti-ban\'></i> Revoke</button>")',
'+"<button class=\'btn bo bs\' onclick=\'del(\\""+k.key+"\\")\'><i class=\'ti ti-trash\'></i></button>"',
'+"</td>";',
'tb.appendChild(tr);',
'});}',
'function renderEv(){',
'var el=document.getElementById("evl");el.innerHTML="";',
'E.slice(0,80).forEach(function(e){',
'var d=document.createElement("div");d.className="er";',
'var c=e.event==="ACTIVATED"||e.event==="VALIDATED"?"#5DCAA5":e.event==="REVOKED"?"#f09595":"#EF9F27";',
'var ts=(e.ts||"").slice(0,16);',
'd.innerHTML="<span class=\'et\'>"+ts+"</span><span class=\'ek\'>"+e.key+"</span><span style=\'font-weight:600;color:"+c+"\'>"+e.event+"</span>";',
'el.appendChild(d);',
'});}',
'function csv(){',
'if(!K.length){toast("No keys","w");return;}',
'var h="key,label,status,hwid,activatedAt,createdAt";',
'var rows=K.map(function(k){return [k.key,k.label||"",k.revoked?"revoked":k.activated?"active":"unused",k.hwid||"",k.activatedAt||"",k.createdAt||""].join(",");});',
'var a=document.createElement("a");',
'a.href="data:text/csv;charset=utf-8,"+encodeURIComponent([h].concat(rows).join("\n"));',
'a.download="quickfire-keys.csv";a.click();',
'toast("Exported","g");}',
'function toast(msg,type){',
'var el=document.getElementById("toast");',
'el.textContent=msg;',
'el.className="toast ts "+(type==="g"?"tg":type==="e"?"te":"tw");',
'clearTimeout(el._t);',
'el._t=setTimeout(function(){el.className="toast";},2800);}',
'</script></body></html>'
].join('');

// Argus SIEM — Server (zero dependencies: raw Node http + fs)
// Reads the JSONL event store, runs the detection engine, serves the dashboard + JSON API.
const http = require('http');
const fs = require('fs');
const path = require('path');
const { detect, RULES } = require('./detections');

const PORT = 3001;
const STORE = path.join(__dirname, 'data', 'events.jsonl');
const PUBLIC = path.join(__dirname, 'public');

const EVENT_NAMES = {
  4624: 'Successful logon', 4625: 'Failed logon', 4634: 'Logoff', 4647: 'User-initiated logoff',
  4648: 'Logon w/ explicit creds', 4672: 'Special privileges assigned', 4688: 'Process created',
  4720: 'Account created', 4722: 'Account enabled', 4724: 'Password reset attempt',
  4728: 'Added to global group', 4732: 'Added to local group', 4756: 'Added to universal group',
  4740: 'Account locked out', 1102: 'Audit log cleared',
};

// ── event store (cached, reloaded when the file changes) ───────────────────────
let _cache = { mtime: 0, events: [] };
function loadEvents() {
  try {
    const stat = fs.statSync(STORE);
    if (stat.mtimeMs === _cache.mtime) return _cache.events;
    const events = [];
    const raw = fs.readFileSync(STORE, 'utf8').replace(/﻿/g, ''); // strip any BOM(s)
    for (const line of raw.split('\n')) {
      if (!line.trim()) continue;
      try { events.push(JSON.parse(line)); } catch (_) {}
    }
    events.sort((a, b) => new Date(a.ts) - new Date(b.ts));
    _cache = { mtime: stat.mtimeMs, events };
  } catch (_) { _cache = { mtime: 0, events: [] }; }
  return _cache.events;
}

// ── stats ──────────────────────────────────────────────────────────────────────
function buildStats(events, alerts) {
  const byEventId = {};
  const targets = {};
  const srcIps = new Set();
  for (const e of events) {
    byEventId[e.eventId] = (byEventId[e.eventId] || 0) + 1;
    if (e.eventId === 4625 && e.user) targets[e.user] = (targets[e.user] || 0) + 1;
    if (e.sourceIp && e.sourceIp !== '-' && e.sourceIp !== '::1' && e.sourceIp !== '127.0.0.1') srcIps.add(e.sourceIp);
  }
  // hourly volume — last 24h
  const now = Date.now(), hourly = [];
  for (let i = 23; i >= 0; i--) {
    const t0 = now - i * 3600000, t1 = t0 + 3600000;
    const count = events.filter(e => { const t = new Date(e.ts).getTime(); return t >= t0 && t < t1; }).length;
    hourly.push({ hour: new Date(t0).getHours(), count });
  }
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const mitre = {};
  for (const a of alerts) {
    sevCounts[a.severity]++;
    mitre[a.mitre.id] = mitre[a.mitre.id] || { id: a.mitre.id, name: a.mitre.name, tactic: a.mitre.tactic, count: 0 };
    mitre[a.mitre.id].count++;
  }
  return {
    totalEvents: events.length,
    firstSeen: events.length ? events[0].ts : null,
    lastSeen: events.length ? events[events.length - 1].ts : null,
    failedLogons: byEventId[4625] || 0,
    successLogons: byEventId[4624] || 0,
    uniqueSourceIps: srcIps.size,
    alertCount: alerts.length,
    byEventId: Object.entries(byEventId).map(([id, n]) => ({ id: +id, name: EVENT_NAMES[id] || `Event ${id}`, count: n })).sort((a, b) => b.count - a.count),
    topTargets: Object.entries(targets).map(([u, n]) => ({ user: u, count: n })).sort((a, b) => b.count - a.count).slice(0, 8),
    hourly,
    severity: sevCounts,
    mitre: Object.values(mitre).sort((a, b) => b.count - a.count),
    rulesActive: RULES.length,
  };
}

// ── http ─────────────────────────────────────────────────────────────────────
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' };
function json(res, obj) { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); }

http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const p = url.pathname;

  if (p === '/api/events') {
    const limit = +url.searchParams.get('limit') || 200;
    const ev = loadEvents();
    return json(res, ev.slice(-limit).reverse().map(e => ({ ...e, eventName: EVENT_NAMES[e.eventId] || `Event ${e.eventId}` })));
  }
  if (p === '/api/alerts') return json(res, detect(loadEvents()));
  if (p === '/api/stats')  { const ev = loadEvents(); return json(res, buildStats(ev, detect(ev))); }
  if (p === '/api/rules')  return json(res, RULES.map(r => ({ id: r.id, name: r.name, severity: r.severity, mitre: r.mitre })));

  // static
  let file = p === '/' ? 'index.html' : p.replace(/^\/+/, '');
  const full = path.join(PUBLIC, file);
  if (full.startsWith(PUBLIC) && fs.existsSync(full)) {
    res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'text/plain' });
    return fs.createReadStream(full).pipe(res);
  }
  res.writeHead(404); res.end('Not found');
}).listen(PORT, () => console.log(`\n  🛡  Argus SIEM → http://localhost:${PORT}\n`));

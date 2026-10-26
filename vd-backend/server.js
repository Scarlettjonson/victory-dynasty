'use strict';
/* Victory Dynasty private inbox API. Stack: Node + Express + SQLite (all free/open-source).
   Security: parameterised SQL only, strict validation, signed guest tokens, rate limits, CORS allow-list,
   argon2id admin login, HttpOnly+Secure+SameSite=Strict session cookie, CSRF token, generic errors. */
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
const argon2 = require('argon2');
const crypto = require('crypto');
const busboy = require('busboy');
const fs = require('fs');
const path = require('path');

const { PORT = 3000, SITE_ORIGIN, ADMIN_USER = 'owner', ADMIN_PASSWORD_HASH, SERVER_SECRET, DB_PATH = './data/chat.db', RETENTION_DAYS = 150 } = process.env;
const ADMIN_ORIGIN = process.env.ADMIN_ORIGIN || SITE_ORIGIN;
if (!SITE_ORIGIN || !ADMIN_PASSWORD_HASH || !SERVER_SECRET || SERVER_SECRET.length < 32) { console.error('Missing or weak .env settings. See .env.example'); process.exit(1); }

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || './data/uploads');   // keep OUTSIDE any public web folder
fs.mkdirSync(UPLOAD_DIR, { recursive: true, mode: 0o700 });
const MAX_IMG = 8 * 1048576, MAX_VID = 30 * 1048576;
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL'); db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS guests(id TEXT PRIMARY KEY, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT, guest_id TEXT NOT NULL REFERENCES guests(id) ON DELETE CASCADE,
  sender TEXT NOT NULL CHECK(sender IN ('guest','agent')), body TEXT NOT NULL, client_id TEXT, created_at INTEGER NOT NULL, att_id TEXT, UNIQUE(guest_id, client_id));
CREATE TABLE IF NOT EXISTS attachments(id TEXT PRIMARY KEY, guest_id TEXT NOT NULL REFERENCES guests(id) ON DELETE CASCADE, mime TEXT NOT NULL, size INTEGER NOT NULL, file TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS ix_msg_guest ON messages(guest_id, created_at);
CREATE TABLE IF NOT EXISTS admin_sessions(token_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires_at INTEGER NOT NULL);`);
// Every query below uses ? placeholders (prepared statements) -> SQL injection is not possible through user input.
const q = {
  addGuest: db.prepare('INSERT INTO guests(id,created_at,last_seen) VALUES(?,?,?)'),
  seen: db.prepare('UPDATE guests SET last_seen=? WHERE id=?'),
  hasGuest: db.prepare('SELECT 1 FROM guests WHERE id=?'),
  addMsg: db.prepare('INSERT OR IGNORE INTO messages(guest_id,sender,body,client_id,created_at) VALUES(?,?,?,?,?)'),
  byClient: db.prepare('SELECT id,created_at FROM messages WHERE guest_id=? AND client_id=?'),
  agentAfter: db.prepare("SELECT id,body,created_at FROM messages WHERE guest_id=? AND sender='agent' AND created_at>=? ORDER BY created_at, id LIMIT 50"),
  threads: db.prepare(`SELECT g.id AS guestId, g.last_seen AS lastSeen, m.body AS last, m.sender AS sender, m.created_at AS at
    FROM guests g JOIN messages m ON m.id=(SELECT MAX(id) FROM messages WHERE guest_id=g.id) ORDER BY m.created_at DESC LIMIT 200`),
  thread: db.prepare('SELECT m.id,m.sender,m.body,m.created_at,m.att_id,a.mime AS att_mime FROM messages m LEFT JOIN attachments a ON a.id=m.att_id WHERE m.guest_id=? ORDER BY m.created_at LIMIT 500'),
  countAtt: db.prepare('SELECT COUNT(*) AS n FROM attachments WHERE guest_id=?'),
  addAtt: db.prepare('INSERT INTO attachments(id,guest_id,mime,size,file,created_at) VALUES(?,?,?,?,?,?)'),
  addMsgAtt: db.prepare('INSERT INTO messages(guest_id,sender,body,client_id,created_at,att_id) VALUES(?,?,?,?,?,?)'),
  getAtt: db.prepare('SELECT mime,file FROM attachments WHERE id=?'),
  oldFiles: db.prepare('SELECT file FROM attachments WHERE guest_id IN (SELECT id FROM guests WHERE last_seen<?)'),
  addSess: db.prepare('INSERT INTO admin_sessions(token_hash,csrf,expires_at) VALUES(?,?,?)'),
  getSess: db.prepare('SELECT csrf,expires_at FROM admin_sessions WHERE token_hash=?'),
  delSess: db.prepare('DELETE FROM admin_sessions WHERE token_hash=?'),
  purgeSess: db.prepare('DELETE FROM admin_sessions WHERE expires_at<?'),
  purgeMsgs: db.prepare('DELETE FROM guests WHERE last_seen<?')   // cascades to messages (privacy: do not keep chats forever)
};

const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const b64u = b => Buffer.from(b).toString('base64url');
const sign = id => b64u(crypto.createHmac('sha256', SERVER_SECRET).update(id).digest());
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const clean = s => String(s).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim();
const GUEST_RE = /^g_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, CLIENT_RE = /^c_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);                       // we run behind ONE proxy (Cloudflare/nginx) so req.ip is the real visitor
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } }, crossOriginResourcePolicy: { policy: 'same-site' } }));
app.use(express.json({ limit: '4kb', strict: true }));
app.use((req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });

/* CORS: only YOUR website may call the guest chat API */
app.use('/api/chat', (req, res, next) => {
  const o = req.get('Origin');
  if (o && o !== SITE_ORIGIN) return res.status(403).json({ error: 'forbidden' });
  if (o) { res.set({ 'Access-Control-Allow-Origin': o, 'Vary': 'Origin', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Max-Age': '600' }); }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const lim = (windowMs, max, keyGenerator) => rateLimit({ windowMs, max, standardHeaders: true, legacyHeaders: false, keyGenerator, message: { error: 'too_many_requests' } });
const byGuest = req => req.guestId;   // guestAuth always runs first

/* ---------- guest API ---------- */
app.post('/api/chat/session', lim(60 * 60e3, 20), (req, res) => {          // 20 new guest IDs / hour / IP
  const id = 'g_' + crypto.randomUUID(), now = Date.now();
  q.addGuest.run(id, now, now);
  res.status(201).json({ guestId: id, token: id + '.' + sign(id) });
});
function guestAuth(req, res, next) {
  const m = /^Bearer (g_[0-9a-f-]{36})\.([A-Za-z0-9_-]{43})$/.exec(req.get('Authorization') || '');
  if (!m || !GUEST_RE.test(m[1]) || !safeEq(sign(m[1]), m[2]) || !q.hasGuest.get(m[1])) return res.status(401).json({ error: 'unauthorized' });
  req.guestId = m[1]; q.seen.run(Date.now(), m[1]); next();
}
app.post('/api/chat/messages', guestAuth, lim(10 * 60e3, 30, byGuest), (req, res) => {
  const b = req.body || {};
  if (typeof b.text !== 'string' || typeof b.clientMessageId !== 'string' || !CLIENT_RE.test(b.clientMessageId)) return res.status(400).json({ error: 'invalid' });
  if (b.website) return res.status(201).json({ id: 'ok', createdAt: new Date().toISOString() });   // honeypot hit: pretend success, store nothing
  const text = clean(b.text);
  if (!text || text.length > 1000) return res.status(400).json({ error: 'invalid' });
  q.addMsg.run(req.guestId, 'guest', text, b.clientMessageId, Date.now());
  const r = q.byClient.get(req.guestId, b.clientMessageId);                 // idempotent: same message sent twice is stored once
  res.status(201).json({ id: 'm' + r.id, createdAt: new Date(r.created_at).toISOString() });
});
app.get('/api/chat/messages', guestAuth, lim(60e3, 40, byGuest), (req, res) => {
  const after = Date.parse(String(req.query.after || '')) || 0;
  res.json({ messages: q.agentAfter.all(req.guestId, after).map(r => ({ id: 'm' + r.id, from: 'agent', text: r.body, createdAt: new Date(r.created_at).toISOString() })) });
});

/* Photo / video upload. Safety: size caps, real file-type check by content ("magic bytes", not the name the user gives),
   random file names, stored outside the web folder, max 20 files per guest, strict rate limit. SVG/HTML/scripts are rejected. */
function sniff(f) {
  const b = Buffer.alloc(16), fd = fs.openSync(f, 'r'); fs.readSync(fd, b, 0, 16, 0); fs.closeSync(fd);
  if (b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF) return ['image/jpeg', 'jpg'];
  if (b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))) return ['image/png', 'png'];
  if (b.subarray(0, 4).toString('latin1') === 'GIF8') return ['image/gif', 'gif'];
  if (b.subarray(0, 4).toString('latin1') === 'RIFF' && b.subarray(8, 12).toString('latin1') === 'WEBP') return ['image/webp', 'webp'];
  if (b.subarray(4, 8).toString('latin1') === 'ftyp') return b.subarray(8, 10).toString('latin1') === 'qt' ? ['video/quicktime', 'mov'] : ['video/mp4', 'mp4'];
  if (b[0] === 0x1A && b[1] === 0x45 && b[2] === 0xDF && b[3] === 0xA3) return ['video/webm', 'webm'];
  return null;
}
app.post('/api/chat/upload', guestAuth, lim(10 * 60e3, 10, byGuest), (req, res) => {
  if (!/^multipart\/form-data/i.test(req.get('Content-Type') || '')) return res.status(415).json({ error: 'invalid' });
  if (q.countAtt.get(req.guestId).n >= 20) return res.status(429).json({ error: 'limit' });
  const id = crypto.randomBytes(16).toString('hex'), tmp = path.join(UPLOAD_DIR, id + '.part');
  const fields = {}; let got = false, tooBig = false, done = false, bb;
  const fail = (code, err) => { if (done) return; done = true; try { req.unpipe(bb); } catch (e) {} fs.unlink(tmp, () => {}); res.status(code).json({ error: err }); };
  try { bb = busboy({ headers: req.headers, limits: { fileSize: MAX_VID, files: 1, fields: 4, fieldSize: 2048, parts: 6 } }); } catch (e) { return res.status(400).json({ error: 'bad_request' }); }
  bb.on('field', (n, v) => { fields[n] = v; });
  bb.on('file', (n, file) => {
    if (got) return file.resume();
    got = true; const ws = fs.createWriteStream(tmp, { flags: 'wx', mode: 0o600 });
    file.on('limit', () => { tooBig = true; });
    ws.on('error', () => fail(500, 'server_error'));
    ws.on('finish', () => {
      if (done) return;
      try {
        if (fields.website) { fs.unlink(tmp, () => {}); done = true; return res.status(201).json({ id: 'ok', createdAt: new Date().toISOString() }); }   // bot trap
        if (tooBig) return fail(413, 'too_large');
        const t = sniff(tmp); if (!t) return fail(415, 'unsupported');
        const size = fs.statSync(tmp).size;
        if (!size || (t[0].startsWith('image/') && size > MAX_IMG)) return fail(size ? 413 : 400, size ? 'too_large' : 'invalid');
        const cid = fields.clientMessageId; if (typeof cid !== 'string' || !CLIENT_RE.test(cid)) return fail(400, 'invalid');
        const caption = typeof fields.text === 'string' ? clean(fields.text).slice(0, 1000) : '';
        const name = id + '.' + t[1], now = Date.now();
        fs.renameSync(tmp, path.join(UPLOAD_DIR, name));
        try { db.transaction(() => { q.addAtt.run(id, req.guestId, t[0], size, name, now); q.addMsgAtt.run(req.guestId, 'guest', caption || (t[0].startsWith('image/') ? '[Photo]' : '[Video]'), cid, now, id); })(); }
        catch (e) { fs.unlink(path.join(UPLOAD_DIR, name), () => {}); }   // duplicate client id -> already stored once
        done = true; const r = q.byClient.get(req.guestId, cid);
        res.status(201).json({ id: 'm' + r.id, createdAt: new Date(r.created_at).toISOString() });
      } catch (e) { fail(500, 'server_error'); }
    });
    file.pipe(ws);
  });
  bb.on('error', () => fail(400, 'bad_request'));
  bb.on('close', () => { if (!got) fail(400, 'invalid'); });
  req.pipe(bb);
});

/* ---------- admin API (your private app) ---------- */
const cookieOf = req => (/(?:^|;\s*)vd_admin=([a-f0-9]{64})/.exec(req.get('Cookie') || '') || [])[1];
app.post('/api/admin/login', lim(15 * 60e3, 5), async (req, res, next) => {   // 5 tries / 15 min / IP
  try {
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string' || password.length > 200) return res.status(400).json({ error: 'invalid' });
    const okUser = safeEq(sha(username), sha(ADMIN_USER));
    const okPass = await argon2.verify(ADMIN_PASSWORD_HASH, password).catch(() => false);   // always runs: no timing hint about the username
    if (!(okUser && okPass)) return res.status(401).json({ error: 'invalid_credentials' });
    const token = crypto.randomBytes(32).toString('hex'), csrf = crypto.randomBytes(24).toString('hex');
    q.addSess.run(sha(token), csrf, Date.now() + 2 * 3600e3);
    res.cookie('vd_admin', token, { httpOnly: true, secure: true, sameSite: 'strict', path: '/api/admin', maxAge: 2 * 3600e3 });
    res.json({ csrf });
  } catch (e) { next(e); }
});
function adminAuth(req, res, next) {
  const t = cookieOf(req), s = t && q.getSess.get(sha(t));
  if (!s || s.expires_at < Date.now()) return res.status(401).json({ error: 'unauthorized' });
  if (req.method !== 'GET') {                                             // CSRF: custom header + matching Origin
    if (!safeEq(req.get('X-CSRF-Token') || '', s.csrf) || (req.get('Origin') && req.get('Origin') !== ADMIN_ORIGIN)) return res.status(403).json({ error: 'forbidden' });
  }
  req.sessHash = sha(t); req.csrf = s.csrf; next();
}
const adminLim = lim(60e3, 120);
app.use('/api/admin', (req, res, next) => (req.path === '/login' ? next() : adminLim(req, res, () => adminAuth(req, res, next))));
app.get('/api/admin/session', (req, res) => res.json({ csrf: req.csrf }));   // lets the admin page recover after reload
app.get('/api/admin/threads', (req, res) => res.json({ threads: q.threads.all() }));
app.get('/api/admin/threads/:id', (req, res) => {
  if (!GUEST_RE.test(req.params.id)) return res.status(400).json({ error: 'invalid' });
  res.json({ messages: q.thread.all(req.params.id) });
});
app.post('/api/admin/threads/:id/reply', (req, res) => {
  const text = typeof (req.body || {}).text === 'string' ? clean(req.body.text) : '';
  if (!GUEST_RE.test(req.params.id) || !q.hasGuest.get(req.params.id) || !text || text.length > 2000) return res.status(400).json({ error: 'invalid' });
  q.addMsg.run(req.params.id, 'agent', text, null, Date.now()); res.status(201).json({ ok: true });
});
app.get('/api/admin/files/:id', (req, res) => {   // only a logged-in admin can open customer files
  if (!/^[0-9a-f]{32}$/.test(req.params.id)) return res.status(400).end();
  const a = q.getAtt.get(req.params.id); if (!a) return res.status(404).end();
  res.set({ 'Content-Type': a.mime, 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'; sandbox", 'Cache-Control': 'private, max-age=3600', 'Content-Disposition': 'inline' });
  res.sendFile(a.file, { root: UPLOAD_DIR, dotfiles: 'deny' }, err => { if (err && !res.headersSent) res.status(404).end(); });
});
app.post('/api/admin/logout', (req, res) => { q.delSess.run(req.sessHash); res.clearCookie('vd_admin', { path: '/api/admin' }); res.json({ ok: true }); });

/* ---------- admin page (static files in ./admin) ---------- */
app.use('/admin', (req, res, next) => {
  res.set({ 'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; media-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", 'X-Robots-Tag': 'noindex, nofollow' });
  next();
}, express.static(path.join(__dirname, 'admin'), { index: 'index.html', dotfiles: 'ignore' }));

/* ---------- safe errors ---------- */
app.use((req, res) => res.status(404).json({ error: 'not_found' }));
app.use((err, req, res, next) => {                                        // never leak stack traces / SQL / paths to the visitor
  console.error(new Date().toISOString(), err && err.message);
  const st = err && err.status >= 400 && err.status < 500 ? err.status : 500;
  res.status(st).json({ error: st === 500 ? 'server_error' : 'bad_request' });
});
setInterval(() => {
  const cutoff = Date.now() - RETENTION_DAYS * 86400e3;
  q.purgeSess.run(Date.now());
  q.oldFiles.all(cutoff).forEach(r => fs.unlink(path.join(UPLOAD_DIR, path.basename(r.file)), () => {}));   // delete the files too, not just DB rows
  q.purgeMsgs.run(cutoff);
}, 3600e3).unref();
app.listen(PORT, '127.0.0.1', () => console.log('Chat API listening on 127.0.0.1:' + PORT));   // only the proxy can reach it

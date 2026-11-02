'use strict';
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT = +process.env.PORT || 3000;
const PASS = process.env.ADMIN_PASSWORD || '';
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const FILE = path.join(DIR, 'poems.json');

if (!PASS || PASS.length < 8) {
  console.error('Set ADMIN_PASSWORD (minimal 8 karakter). Contoh: ADMIN_PASSWORD="kata-sandi-kuat" node server.js');
  process.exit(1);
}

const SEED = [
  { title: 'Hujan Pertama', author: 'Penghuni Rumah', category: 'Alam',
    text: 'Hujan pertama jatuh di genting tua,\nmengetuk pintu tanah yang lama haus.\nAku duduk, menghitung tetes yang datang,\nseperti menghitung kabar yang tak kunjung lewat.' },
  { title: 'Secangkir Pagi', author: 'Penghuni Rumah', category: 'Keseharian',
    text: 'Uap dari cangkir menulis namamu di udara,\nlalu lupa mengeja huruf terakhirnya.\nPagi ini aku belajar sabar\ndari gula yang larut tanpa bunyi.' },
  { title: 'Jarak', author: 'Penghuni Rumah', category: 'Rindu',
    text: 'Kita dipisah sebentang peta,\ntetapi malam yang sama menutup mata kita.\nJika bulan adalah surat,\nkubaca ia dua kali sebelum tidur.' }
];

let poems = [];
function save() {
  fs.mkdirSync(DIR, { recursive: true });
  const tmp = FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(poems, null, 2));
  fs.renameSync(tmp, FILE);
}
function load() {
  try { poems = JSON.parse(fs.readFileSync(FILE, 'utf8')); }
  catch (e) {
    if (e.code !== 'ENOENT') throw e; // file rusak: jangan ditimpa diam-diam
    const now = Date.now();
    poems = SEED.map((p, i) => ({ id: crypto.randomBytes(6).toString('hex'), ...p, createdAt: now - i * 1000 }));
    save();
  }
}
load();

const PAGE = fs.readFileSync(path.join(__dirname, 'public', 'index.html'));
const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('hex');
const sha = s => crypto.createHash('sha256').update(String(s)).digest();

function isAdmin(req) {
  const m = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return false;
  const [exp, sig] = m[1].split('.');
  if (!exp || !sig || !(+exp > Date.now())) return false;
  const a = Buffer.from(sig), b = Buffer.from(sign(exp));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const tries = new Map();
function limited(ip) {
  const now = Date.now(), t = tries.get(ip) || { n: 0, at: now };
  if (now - t.at > 60000) { t.n = 0; t.at = now; }
  t.n++; tries.set(ip, t);
  return t.n > 5;
}
function readBody(req) {
  return new Promise((ok, no) => {
    let d = '';
    req.on('data', c => { d += c; if (d.length > 1e5) { no(new Error('Data terlalu besar')); req.destroy(); } });
    req.on('end', () => { try { ok(JSON.parse(d || '{}')); } catch (e) { no(new Error('JSON tidak valid')); } });
  });
}
function clean(b) {
  const f = (v, n) => typeof v === 'string' ? v.trim().slice(0, n) : '';
  const t = { title: f(b.title, 200), author: f(b.author, 100), category: f(b.category, 50),
    text: typeof b.text === 'string' ? b.text.replace(/\s+$/, '').slice(0, 20000) : '' };
  return t.title && t.text ? t : null;
}

http.createServer(async (req, res) => {
  const send = (code, obj, headers) => {
    res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store', ...headers });
    res.end(JSON.stringify(obj));
  };
  try {
    const p = new URL(req.url, 'http://x').pathname, m = req.method;
    if (m === 'GET' && (p === '/' || p === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY' });
      return res.end(PAGE);
    }
    if (!p.startsWith('/api/')) return send(404, { error: 'Halaman tidak ditemukan' });
    if (m === 'GET' && p === '/api/poems') return send(200, [...poems].sort((a, b) => b.createdAt - a.createdAt));
    if (m === 'GET' && p === '/api/me') return send(200, { admin: isAdmin(req) });

    if ((m === 'POST' || m === 'PUT') && !/^application\/json/.test(req.headers['content-type'] || ''))
      return send(415, { error: 'Content-Type harus application/json' });

    if (m === 'POST' && p === '/api/login') {
      const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
      if (limited(ip)) return send(429, { error: 'Terlalu banyak percobaan. Tunggu semenit.' });
      const b = await readBody(req);
      if (!crypto.timingSafeEqual(sha(b.password || ''), sha(PASS))) return send(401, { error: 'Kata sandi salah' });
      const exp = String(Date.now() + 7 * 864e5);
      const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
      return send(200, { admin: true }, { 'Set-Cookie': `sid=${exp}.${sign(exp)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800${secure}` });
    }
    if (m === 'POST' && p === '/api/logout') return send(200, { admin: false }, { 'Set-Cookie': 'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });

    const idm = /^\/api\/poems\/([a-f0-9]+)$/.exec(p);
    if ((m === 'POST' && p === '/api/poems') || (idm && (m === 'PUT' || m === 'DELETE'))) {
      if (!isAdmin(req)) return send(401, { error: 'Hanya admin yang boleh mengubah puisi' });
      if (m === 'POST') {
        const t = clean(await readBody(req));
        if (!t) return send(400, { error: 'Judul dan isi puisi wajib diisi' });
        const poem = { id: crypto.randomBytes(6).toString('hex'), ...t, createdAt: Date.now() };
        poems.push(poem); save(); return send(201, poem);
      }
      const i = poems.findIndex(x => x.id === idm[1]);
      if (i < 0) return send(404, { error: 'Puisi tidak ditemukan' });
      if (m === 'DELETE') { poems.splice(i, 1); save(); return send(200, { ok: true }); }
      const t = clean(await readBody(req));
      if (!t) return send(400, { error: 'Judul dan isi puisi wajib diisi' });
      poems[i] = { ...poems[i], ...t }; save(); return send(200, poems[i]);
    }
    send(404, { error: 'Endpoint tidak ditemukan' });
  } catch (e) {
    send(400, { error: e.message || 'Permintaan tidak valid' });
  }
}).listen(PORT, () => console.log('Rumah Puisi berjalan di http://localhost:' + PORT));
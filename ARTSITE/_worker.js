// ISMAILTENNI ART - accounts (sign up / log in) on Cloudflare Pages + D1.
// Needs a D1 database bound to this project with the variable name: DB
const enc = new TextEncoder();
const WORK = /^[a-z0-9_-]{1,40}$/i;
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers } });

async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 }, key, 256);
  return b64(bits);
}
async function sha256(text) { return b64(await crypto.subtle.digest('SHA-256', enc.encode(text))); }
function sessionCookie(token, maxAge) {
  return `session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}
function getCookie(req, name) {
  const m = (req.headers.get('cookie') || '').match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return m ? m[1] : null;
}
async function currentUser(env, req) {
  const t = getCookie(req, 'session');
  if (!t) return null;
  const h = await sha256(t);
  return await env.DB.prepare('SELECT u.id, u.name, u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?')
    .bind(h, Date.now()).first();
}
async function startSession(env, userId) {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const token = Array.from(raw, (b) => b.toString(16).padStart(2, '0')).join('');
  const maxAge = 60 * 60 * 24 * 30;
  await env.DB.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(await sha256(token), userId, Date.now() + maxAge * 1000).run();
  return sessionCookie(token, maxAge);
}
async function tooMany(env, key) {
  const since = Date.now() - 15 * 60 * 1000;
  const r = await env.DB.prepare('SELECT COUNT(*) AS n FROM attempts WHERE key = ? AND at > ?').bind(key, since).first();
  return r && r.n >= 8;
}
function isAdmin(env, me) { return !!(me && env.ADMIN_EMAIL && String(env.ADMIN_EMAIL).trim().toLowerCase() === me.email); }
async function note(env, key) {
  await env.DB.prepare('INSERT INTO attempts (key, at) VALUES (?, ?)').bind(key, Date.now()).run();
}


const SCHEMA = [
  'CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, salt TEXT NOT NULL, hash TEXT NOT NULL, created_at INTEGER NOT NULL)',
  'CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL)',
  'CREATE TABLE IF NOT EXISTS attempts (key TEXT NOT NULL, at INTEGER NOT NULL)',
  'CREATE INDEX IF NOT EXISTS attempts_key ON attempts (key, at)',
  'CREATE TABLE IF NOT EXISTS likes (work_id TEXT NOT NULL, user_id INTEGER NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (work_id, user_id))',
  'CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY AUTOINCREMENT, work_id TEXT NOT NULL, user_id INTEGER NOT NULL, text TEXT NOT NULL, created_at INTEGER NOT NULL)',
  'CREATE INDEX IF NOT EXISTS comments_work ON comments (work_id, created_at)',
  'CREATE TABLE IF NOT EXISTS subscribers (email TEXT PRIMARY KEY, created_at INTEGER NOT NULL)',
  'CREATE TABLE IF NOT EXISTS content (k TEXT PRIMARY KEY, v TEXT NOT NULL, updated_at INTEGER NOT NULL)',
  'CREATE TABLE IF NOT EXISTS media (id TEXT PRIMARY KEY, mime TEXT NOT NULL, n INTEGER NOT NULL, created_at INTEGER NOT NULL)',
  'CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, contact TEXT NOT NULL, kind TEXT, size TEXT, budget TEXT, idea TEXT NOT NULL, ref TEXT, created_at INTEGER NOT NULL)',
  'CREATE TABLE IF NOT EXISTS hits (day TEXT NOT NULL, k TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (day, k))',
  'CREATE TABLE IF NOT EXISTS visitors (day TEXT NOT NULL, h TEXT NOT NULL, PRIMARY KEY (day, h))',
  'CREATE TABLE IF NOT EXISTS review_links (token TEXT PRIMARY KEY, name TEXT NOT NULL, created_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0)',
  'CREATE TABLE IF NOT EXISTS client_reviews (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, stars INTEGER NOT NULL, text TEXT NOT NULL, created_at INTEGER NOT NULL, approved INTEGER NOT NULL DEFAULT 0)',
  'CREATE TABLE IF NOT EXISTS waitlist (product TEXT NOT NULL, email TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (product, email))',
  'CREATE TABLE IF NOT EXISTS media_chunks (id TEXT NOT NULL, i INTEGER NOT NULL, d TEXT NOT NULL, PRIMARY KEY (id, i))',
];

// ---------- site content (editable by the owner) ----------
const MIMES = { 'image/jpeg': 1, 'image/png': 1, 'image/webp': 1 };
const RATIOS = ['3 / 4', '1 / 1', '4 / 5', '16 / 9', '2 / 3', '4 / 3'];
const str = (v, n) => String(v == null ? '' : v).slice(0, n);
function okUrl(u) { return typeof u === 'string' && /^(\/api\/media\/[a-f0-9]{8,32}|assets\/[A-Za-z0-9._-]+)$/.test(u); }
function cleanShots(a, max) {
  return (Array.isArray(a) ? a : []).slice(0, max).map((s) => (typeof s === 'string' ? { src: s, label: '' } : s))
    .filter((s) => s && okUrl(s.src)).map((s) => ({ src: s.src, label: str(s.label, 60) }));
}
function cleanFilm(f) {
  if (!f || typeof f !== 'object') return null;
  const title = str(f.title, 80);
  const raw = str(f.url || f.link || '', 300).trim();
  let m;
  if ((m = raw.match(/^https?:\/\/(?:www\.|m\.)?(?:youtube\.com\/(?:watch\?(?:[^#]*&)?v=|shorts\/|embed\/)|youtu\.be\/)([A-Za-z0-9_-]{11})/i)))
    return { title, url: raw, embed: 'https://www.youtube-nocookie.com/embed/' + m[1] };
  if ((m = raw.match(/^https?:\/\/(?:www\.)?vimeo\.com\/(?:video\/)?(\d{5,12})/i)))
    return { title, url: raw, embed: 'https://player.vimeo.com/video/' + m[1] };
  if (/^https:\/\/[^\s"'<>]+\.(mp4|webm|mov)(\?[^\s"'<>]*)?$/i.test(raw)) return { title, file: raw, url: raw };
  if (/^https:\/\/[^\s"'<>]+$/i.test(raw)) return { title, url: raw };
  return null;
}

const SCH = {
  shop: { name: 's80', price: 's40', photo: 'img', pay: 'url', edition: 'n', left: 'n', ends: 's10' },
  prints: { name: 's60', price: 's20', pay: 'url' },
  gifts: { name: 's80', price: 's40', pay: 'url' },
  reviews: { name: 's60', text: 's500', stars: 'n' },
  behind: { photo: 'img', caption: 's100' },
  wallpapers: { photo: 'img', title: 's80' },
  spotlight: { on: 's3', title: 's100', text: 's800', image: 'img', price: 's40', pay: 'url' },
  ba: { before: 'img', after: 'img', caption: 's100' },
  about: { portrait: 'img', t1: 's700', t2: 's700', t3: 's700', p1: 'img', p2: 'img', p3: 'img', poster: 'img', vurl: 's300' },
  settings: { payDefault: 'url', payLabel: 's30' },
  posts: { title: 's100', text: 's6000', image: 'img', date: 's10' },
  challenge: { on: 's3', title: 's100', text: 's800', prize: 's100', deadline: 's10' },
};
function cleanRow(o, sch) {
  const out = {};
  if (!o || typeof o !== 'object') return out;
  for (const [k, t] of Object.entries(sch)) {
    const v = o[k];
    if (t === 'img') { if (okUrl(v)) out[k] = v; }
    else if (t === 'url') { const u = str(v, 300).trim(); if (/^https:\/\/[^\s"'<>]+$/i.test(u)) out[k] = u; }
    else if (t === 'n') { const x = parseInt(v, 10); if (Number.isFinite(x) && x >= 0 && x < 100000) out[k] = x; }
    else { const x = str(v, +t.slice(1)).trim(); if (x) out[k] = x; }
  }
  return out;
}
function cleanList(a, sch, max, need) {
  return (Array.isArray(a) ? a : []).slice(0, max).map((r) => cleanRow(r, sch)).filter((r) => need.some((k) => r[k]));
}

function cleanContent(b) {
  const works = (Array.isArray(b.works) ? b.works : []).slice(0, 80).map((w, i) => {
    if (!w || !okUrl(w.cover)) return null;
    let id = str(w.id, 40);
    if (!WORK.test(id)) id = 'w' + Date.now().toString(36) + i;
    return { id, series: str(w.series, 40), title: str(w.title, 100), meta: str(w.meta, 100), desc: str(w.desc, 2000),
      ratio: RATIOS.includes(w.ratio) ? w.ratio : '3 / 4', status: str(w.status, 24), cover: w.cover,
      price: str(w.price, 40).trim(), pay: (() => { const u = str(w.pay, 300).trim(); return /^https:\/\/[^\s"'<>]+$/i.test(u) ? u : ''; })(),
      shots: cleanShots(w.shots, 30), process: cleanShots(w.process, 30) };
  }).filter(Boolean);
  const photos = (Array.isArray(b.photos) ? b.photos : []).slice(0, 200).filter(okUrl);
  const films = (Array.isArray(b.films) ? b.films : []).slice(0, 40).map(cleanFilm).filter(Boolean);
  const texts = {};
  if (b.texts && typeof b.texts === 'object') {
    for (const [k, v] of Object.entries(b.texts).slice(0, 500)) {
      if (!/^[tyxz]:[A-Za-z0-9_]{1,40}$/.test(k) || !v || typeof v !== 'object') continue;
      const o = {};
      for (const l of ['en', 'fr', 'ar']) if (typeof v[l] === 'string' && v[l].trim()) o[l] = str(v[l].trim(), 600);
      if (Object.keys(o).length) texts[k] = o;
    }
  }
  const pr = b.pricing && typeof b.pricing === 'object' ? b.pricing : {};
  const pnum = { name: 's60', price: 's10' };
  const pricing = { cur: str(pr.cur, 6).trim(), person: str(pr.person, 10).trim(), rush: str(pr.rush, 10).trim(), note: str(pr.note, 300).trim(),
    sizes: cleanList(pr.sizes, pnum, 12, ['name']), styles: cleanList(pr.styles, pnum, 12, ['name']) };
  const imgs = {};
  if (b.imgs && typeof b.imgs === 'object') {
    for (const [k, v] of Object.entries(b.imgs).slice(0, 60)) {
      if (/^[a-f0-9]{32}\.(png|jpg|webp)$/.test(k) && typeof v === 'string' && /^\/api\/media\/[a-f0-9]{8,32}$/.test(v)) imgs[k] = v;
    }
  }
  const extra = {
    imgs, pricing,
    shop: cleanList(b.shop, SCH.shop, 40, ['name', 'photo']),
    prints: cleanList(b.prints, SCH.prints, 12, ['name']),
    gifts: cleanList(b.gifts, SCH.gifts, 12, ['name', 'price']),
    reviews: cleanList(b.reviews, SCH.reviews, 40, ['text']),
    behind: cleanList(b.behind, SCH.behind, 60, ['photo']),
    wallpapers: cleanList(b.wallpapers, SCH.wallpapers, 30, ['photo']),
    timelapse: (Array.isArray(b.timelapse) ? b.timelapse : []).slice(0, 20).map(cleanFilm).filter(Boolean),
    spotlight: cleanRow(b.spotlight, SCH.spotlight),
    ba: cleanRow(b.ba, SCH.ba),
    about: (() => { const a = cleanRow(b.about, SCH.about); const v = cleanFilm({ url: a.vurl }); if (v) a.video = v; return a; })(),
    settings: cleanRow(b.settings, SCH.settings),
    posts: cleanList(b.posts, SCH.posts, 80, ['title']),
    challenge: cleanRow(b.challenge, SCH.challenge),
  };
  return { works, photos, films, texts, ...extra };
}
function mediaIds(obj) {
  const ids = new Set();
  JSON.stringify(obj).replace(/\/api\/media\/([a-f0-9]{8,32})/g, (_, id) => { ids.add(id); return ''; });
  return ids;
}
async function injectContent(env, req, url) {
  const res = await env.ASSETS.fetch(new Request(url.origin + '/', { method: 'GET' }));
  const headers = new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-cache' });
  let html = await res.text();
  let share = '/share.jpg';
  try {
    await ensureSchema(env);
    const row = await env.DB.prepare("SELECT v FROM content WHERE k = 'site'").first();
    if (row && row.v) {
      const saved = JSON.parse(row.v);
      const a = html.indexOf('var C=');
      const b = html.indexOf(';\nfunction E(', a);
      if (a > -1 && b > a) {
        const data = JSON.stringify(saved).replace(/</g, '\\u003c');
        html = html.slice(0, a) + 'var C=' + data + html.slice(b);
      }
      const sp = saved.spotlight && saved.spotlight.on && saved.spotlight.image;
      if (sp && okUrl(sp)) share = sp.startsWith('/') ? sp : '/' + sp;
    }
  } catch (e) { /* if the database is not ready, show the normal page */ }
  html = html.split('{{ORIGIN}}').join(url.origin).split('{{SHARE}}').join(url.origin + share);
  return new Response(html, { status: 200, headers });
}
async function secretKey(env) {
  let raw = env.NEWSLETTER_SECRET;
  if (!raw) {
    const row = await env.DB.prepare("SELECT v FROM content WHERE k = 'secret'").first();
    if (row && row.v) raw = row.v;
    else {
      raw = b64(crypto.getRandomValues(new Uint8Array(32)).buffer);
      await env.DB.prepare("INSERT OR IGNORE INTO content (k, v, updated_at) VALUES ('secret', ?, ?)").bind(raw, Date.now()).run();
      const again = await env.DB.prepare("SELECT v FROM content WHERE k = 'secret'").first();
      raw = again.v;
    }
  }
  return crypto.subtle.importKey('raw', enc.encode(raw), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}
async function unsubToken(env, email) {
  const sig = await crypto.subtle.sign('HMAC', await secretKey(env), enc.encode(email));
  return [...new Uint8Array(sig)].slice(0, 16).map((x) => x.toString(16).padStart(2, '0')).join('');
}
const escH = (t) => String(t == null ? '' : t).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function b64bytes(s) {
  const bin = atob(s); const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function serveMedia(env, req, id) {
  const cache = caches.default;
  const hit = await cache.match(req);
  if (hit) return hit;
  const m = await env.DB.prepare('SELECT mime, n FROM media WHERE id = ?').bind(id).first();
  if (!m) return new Response('Not found', { status: 404 });
  const rows = await env.DB.prepare('SELECT d FROM media_chunks WHERE id = ? ORDER BY i').bind(id).all();
  const parts = (rows.results || []).map((r) => b64bytes(r.d));
  let total = 0; parts.forEach((p) => { total += p.length; });
  const all = new Uint8Array(total); let o = 0; parts.forEach((p) => { all.set(p, o); o += p.length; });
  const res = new Response(all, { headers: { 'content-type': m.mime, 'cache-control': 'public, max-age=31536000, immutable' } });
  try { await cache.put(req, res.clone()); } catch (e) {}
  return res;
}

let schemaReady = null;
function ensureSchema(env) {
  if (!schemaReady) schemaReady = env.DB.batch(SCHEMA.map((q) => env.DB.prepare(q))).catch((e) => { schemaReady = null; throw e; });
  return schemaReady;
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith('/api/')) {
      if (url.pathname === '/robots.txt') return new Response('User-agent: *\nAllow: /\nDisallow: /api/\nSitemap: ' + url.origin + '/sitemap.xml\n', { headers: { 'content-type': 'text/plain; charset=utf-8' } });
      if (url.pathname === '/sitemap.xml') return new Response('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>' + url.origin + '/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url><url><loc>' + url.origin + '/play</loc><changefreq>monthly</changefreq><priority>0.3</priority></url></urlset>\n', { headers: { 'content-type': 'application/xml; charset=utf-8' } });
      if ((url.pathname === '/' || url.pathname === '/index.html') && req.method === 'GET') return injectContent(env, req, url);
      return env.ASSETS.fetch(req);
    }
    if (!env.DB) return json({ error: 'The database is not connected yet.' }, 503);
    try {
      await ensureSchema(env);
      if (url.pathname === '/api/me' && req.method === 'GET') {
        const u = await currentUser(env, req);
        return json({ user: u ? { name: u.name, email: u.email } : null, admin: isAdmin(env, u) });
      }
      if (url.pathname === '/api/counts' && req.method === 'GET') {
        const l = await env.DB.prepare('SELECT work_id AS id, COUNT(*) AS n FROM likes GROUP BY work_id').all();
        const c = await env.DB.prepare('SELECT work_id AS id, COUNT(*) AS n FROM comments GROUP BY work_id').all();
        const out = {};
        (l.results || []).forEach((r) => { out[r.id] = { likes: r.n, comments: 0 }; });
        (c.results || []).forEach((r) => { (out[r.id] = out[r.id] || { likes: 0, comments: 0 }).comments = r.n; });
        return json(out);
      }
      if (url.pathname === '/api/reviews' && req.method === 'GET') {
        const r = await env.DB.prepare('SELECT name, stars, text FROM client_reviews WHERE approved = 1 ORDER BY created_at DESC LIMIT 60').all();
        return json({ reviews: r.results || [] });
      }
      if (url.pathname === '/api/review/check' && req.method === 'GET') {
        const t = String(url.searchParams.get('token') || '').slice(0, 40);
        const r = await env.DB.prepare('SELECT name FROM review_links WHERE token = ? AND used = 0').bind(t).first();
        if (!r) return json({ error: 'This review link is not valid or was already used.' }, 404);
        return json({ name: r.name });
      }
      if (url.pathname === '/api/admin/reviews' && req.method === 'GET') {
        const me = await currentUser(env, req);
        if (!isAdmin(env, me)) return json({ error: 'Owner only.' }, 403);
        const rv = await env.DB.prepare('SELECT id, name, stars, text, created_at, approved FROM client_reviews ORDER BY created_at DESC LIMIT 200').all();
        const lk = await env.DB.prepare('SELECT token, name, used, created_at FROM review_links ORDER BY created_at DESC LIMIT 100').all();
        return json({ reviews: rv.results || [], links: lk.results || [] });
      }
      if (url.pathname === '/api/admin/waitlist' && req.method === 'GET') {
        const me = await currentUser(env, req);
        if (!isAdmin(env, me)) return json({ error: 'Owner only.' }, 403);
        const r = await env.DB.prepare('SELECT product, email, created_at FROM waitlist ORDER BY created_at DESC LIMIT 2000').all();
        return json({ waitlist: r.results || [] });
      }
      if (url.pathname === '/api/admin/backup' && req.method === 'GET') {
        const me = await currentUser(env, req);
        if (!isAdmin(env, me)) return json({ error: 'Owner only.' }, 403);
        const all = async (q) => ((await env.DB.prepare(q).all()).results || []);
        const one = async (k) => { const r = await env.DB.prepare('SELECT v FROM content WHERE k = ?').bind(k).first(); try { return r && r.v ? JSON.parse(r.v) : null; } catch (e) { return null; } };
        const site = await one('site');
        return json({
          kind: 'ismailtenni-art-backup', version: 1, created: new Date().toISOString(), site, orders: await one('orders') || [],
          subscribers: await all('SELECT email, created_at FROM subscribers'),
          waitlist: await all('SELECT product, email, created_at FROM waitlist'),
          reviews: await all('SELECT name, stars, text, created_at, approved FROM client_reviews'),
          requests: await all('SELECT name, contact, kind, size, budget, idea, ref, created_at FROM requests'),
          members: await all('SELECT name, email, created_at FROM users'),
          media: site ? [...mediaIds(site)] : [],
        });
      }
      if (url.pathname === '/api/unsubscribe' && req.method === 'GET') {
        const em = String(url.searchParams.get('e') || '').trim().toLowerCase().slice(0, 120);
        const ok = em && (await unsubToken(env, em)) === url.searchParams.get('t');
        if (ok) await env.DB.prepare('DELETE FROM subscribers WHERE email = ?').bind(em).run();
        const msg = ok ? 'You are unsubscribed. / Vous \u00eates d\u00e9sinscrit(e). / \u062a\u0645 \u0625\u0644\u063a\u0627\u0621 \u0627\u0634\u062a\u0631\u0627\u0643\u0643.' : 'This link is not valid.';
        return new Response('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ISMAILTENNI ART</title><body style="background:#070b1c;color:#fff;font-family:system-ui,sans-serif;display:flex;min-height:90vh;align-items:center;justify-content:center;text-align:center;padding:20px"><div><h1 style="font-weight:400;letter-spacing:.12em">ISMAILTENNI ART</h1><p>' + escH(msg) + '</p><p><a style="color:#a8d6ff" href="/">Back to the site</a></p></div>', { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
      }
      if (url.pathname === '/api/admin/subscribers' && req.method === 'GET') {
        const me = await currentUser(env, req);
        if (!isAdmin(env, me)) return json({ error: 'Owner only.' }, 403);
        const r = await env.DB.prepare('SELECT email, created_at FROM subscribers ORDER BY created_at DESC LIMIT 5000').all();
        return json({ subscribers: r.results || [], canSend: !!(env.RESEND_API_KEY && env.MAIL_FROM) });
      }
      if (url.pathname === '/api/mylikes' && req.method === 'GET') {
        const me = await currentUser(env, req);
        if (!me) return json({ works: null });
        const r = await env.DB.prepare('SELECT work_id FROM likes WHERE user_id = ? ORDER BY created_at DESC LIMIT 200').bind(me.id).all();
        return json({ works: (r.results || []).map((x) => x.work_id) });
      }
      if (url.pathname === '/api/social' && req.method === 'GET') {
        const work = url.searchParams.get('work') || '';
        if (!WORK.test(work)) return json({ error: 'Bad request' }, 400);
        const me = await currentUser(env, req);
        const lk = await env.DB.prepare('SELECT COUNT(*) AS n FROM likes WHERE work_id = ?').bind(work).first();
        const mine = me ? await env.DB.prepare('SELECT 1 AS x FROM likes WHERE work_id = ? AND user_id = ?').bind(work, me.id).first() : null;
        const cm = await env.DB.prepare('SELECT c.id, c.text, c.created_at, u.name, c.user_id FROM comments c JOIN users u ON u.id = c.user_id WHERE c.work_id = ? ORDER BY c.created_at DESC LIMIT 60').bind(work).all();
        return json({ likes: lk ? lk.n : 0, liked: !!mine, me: me ? { name: me.name } : null,
          comments: (cm.results || []).map((r) => ({ id: r.id, name: r.name, text: r.text, at: r.created_at, mine: !!me && (me.id === r.user_id || isAdmin(env, me)) })) });
      }
      if (url.pathname === '/api/order' && req.method === 'GET') {
        const code = String(url.searchParams.get('code') || '').trim().toUpperCase().slice(0, 30);
        const ip = req.headers.get('cf-connecting-ip') || 'x';
        if (await tooMany(env, 'order:' + ip)) return json({ error: 'Too many tries. Please wait a few minutes.' }, 429);
        await note(env, 'order:' + ip);
        const row = await env.DB.prepare("SELECT v FROM content WHERE k = 'orders'").first();
        let list = []; try { list = JSON.parse((row && row.v) || '[]'); } catch (e) {}
        const o = code && list.find((x) => String(x.code || '').toUpperCase() === code);
        if (!o) return json({ error: 'Not found' }, 404);
        return json({ name: o.name || '', stage: Math.min(5, Math.max(1, +o.stage || 1)), note: o.note || '' });
      }
      if (url.pathname === '/api/admin/orders' && req.method === 'GET') {
        const me = await currentUser(env, req);
        if (!isAdmin(env, me)) return json({ error: 'Owner only.' }, 403);
        const row = await env.DB.prepare("SELECT v FROM content WHERE k = 'orders'").first();
        let list = []; try { list = JSON.parse((row && row.v) || '[]'); } catch (e) {}
        return json({ orders: list });
      }
      if (url.pathname === '/api/admin/requests' && req.method === 'GET') {
        const me = await currentUser(env, req);
        if (!isAdmin(env, me)) return json({ error: 'Owner only.' }, 403);
        const r = await env.DB.prepare('SELECT id, name, contact, kind, size, budget, idea, ref, created_at FROM requests ORDER BY created_at DESC LIMIT 100').all();
        return json({ requests: r.results || [] });
      }
      const mm = url.pathname.match(/^\/api\/media\/([a-f0-9]{8,32})$/);
      if (mm && req.method === 'GET') return serveMedia(env, req, mm[1]);
      if (req.method !== 'POST') return json({ error: 'Not found' }, 404);
      const origin = req.headers.get('origin');
      if (origin && new URL(origin).host !== url.host) return json({ error: 'Not allowed' }, 403);
      const body = await req.json().catch(() => ({}));

      if (url.pathname === '/api/signup') {
        const name = String(body.name || '').trim().slice(0, 60);
        const email = String(body.email || '').trim().toLowerCase().slice(0, 120);
        const password = String(body.password || '');
        if (!name) return json({ error: 'Please enter your name.' }, 400);
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json({ error: 'Please enter a valid email.' }, 400);
        if (password.length < 8 || password.length > 200) return json({ error: 'Password must be at least 8 characters.' }, 400);
        const ip = req.headers.get('cf-connecting-ip') || 'x';
        if (await tooMany(env, 'signup:' + ip)) return json({ error: 'Too many tries. Please wait a few minutes.' }, 429);
        await note(env, 'signup:' + ip);
        const exists = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
        if (exists) return json({ error: 'That email already has an account. Try logging in.' }, 409);
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const hash = await hashPassword(password, salt);
        const r = await env.DB.prepare('INSERT INTO users (name, email, salt, hash, created_at) VALUES (?, ?, ?, ?, ?)')
          .bind(name, email, b64(salt), hash, Date.now()).run();
        const cookie = await startSession(env, r.meta.last_row_id);
        return json({ user: { name, email } }, 200, { 'set-cookie': cookie });
      }

      if (url.pathname === '/api/login') {
        const email = String(body.email || '').trim().toLowerCase().slice(0, 120);
        const password = String(body.password || '');
        const key = 'login:' + email + ':' + (req.headers.get('cf-connecting-ip') || 'x');
        if (await tooMany(env, key)) return json({ error: 'Too many tries. Please wait a few minutes.' }, 429);
        const u = await env.DB.prepare('SELECT id, name, email, salt, hash FROM users WHERE email = ?').bind(email).first();
        const ok = u && (await hashPassword(password, unb64(u.salt))) === u.hash;
        if (!ok) { await note(env, key); return json({ error: 'Wrong email or password.' }, 401); }
        const cookie = await startSession(env, u.id);
        return json({ user: { name: u.name, email: u.email } }, 200, { 'set-cookie': cookie });
      }

      if (url.pathname === '/api/like') {
        const me = await currentUser(env, req);
        if (!me) return json({ error: 'Please log in to like.' }, 401);
        const work = String(body.work || '');
        if (!WORK.test(work)) return json({ error: 'Bad request' }, 400);
        const had = await env.DB.prepare('SELECT 1 AS x FROM likes WHERE work_id = ? AND user_id = ?').bind(work, me.id).first();
        if (had) await env.DB.prepare('DELETE FROM likes WHERE work_id = ? AND user_id = ?').bind(work, me.id).run();
        else await env.DB.prepare('INSERT INTO likes (work_id, user_id, created_at) VALUES (?, ?, ?)').bind(work, me.id, Date.now()).run();
        const lk = await env.DB.prepare('SELECT COUNT(*) AS n FROM likes WHERE work_id = ?').bind(work).first();
        return json({ liked: !had, likes: lk.n });
      }
      if (url.pathname === '/api/comment') {
        const me = await currentUser(env, req);
        if (!me) return json({ error: 'Please log in to comment.' }, 401);
        const work = String(body.work || '');
        const text = String(body.text || '').trim().slice(0, 500);
        if (!WORK.test(work) || !text) return json({ error: 'Write something first.' }, 400);
        if (await tooMany(env, 'comment:' + me.id)) return json({ error: 'Slow down a little, then try again.' }, 429);
        await note(env, 'comment:' + me.id);
        const now = Date.now();
        const r = await env.DB.prepare('INSERT INTO comments (work_id, user_id, text, created_at) VALUES (?, ?, ?, ?)').bind(work, me.id, text, now).run();
        return json({ comment: { id: r.meta.last_row_id, name: me.name, text, at: now, mine: true } });
      }
      if (url.pathname === '/api/comment/delete') {
        const me = await currentUser(env, req);
        if (!me) return json({ error: 'Please log in.' }, 401);
        if (isAdmin(env, me)) await env.DB.prepare('DELETE FROM comments WHERE id = ?').bind(Number(body.id) || 0).run();
        else await env.DB.prepare('DELETE FROM comments WHERE id = ? AND user_id = ?').bind(Number(body.id) || 0, me.id).run();
        return json({ ok: true });
      }
      if (url.pathname === '/api/review') {
        const ip = req.headers.get('cf-connecting-ip') || 'x';
        if (await tooMany(env, 'rev:' + ip)) return json({ error: 'Too many tries. Please wait a few minutes.' }, 429);
        await note(env, 'rev:' + ip);
        const t = String(body.token || '').slice(0, 40);
        const link = await env.DB.prepare('SELECT name FROM review_links WHERE token = ? AND used = 0').bind(t).first();
        if (!link) return json({ error: 'This review link is not valid or was already used.' }, 404);
        const stars = Math.min(5, Math.max(1, parseInt(body.stars, 10) || 5));
        const text = str(body.text, 600).trim(), name = str(body.name, 60).trim() || link.name;
        if (text.length < 3) return json({ error: 'Please write a few words.' }, 400);
        await env.DB.batch([
          env.DB.prepare('INSERT INTO client_reviews (name, stars, text, created_at, approved) VALUES (?, ?, ?, ?, 0)').bind(name, stars, text, Date.now()),
          env.DB.prepare('UPDATE review_links SET used = 1 WHERE token = ?').bind(t),
        ]);
        return json({ ok: true });
      }
      if (url.pathname === '/api/waitlist') {
        const email = String(body.email || '').trim().toLowerCase().slice(0, 120), product = str(body.product, 100).trim();
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || !product) return json({ error: 'Please enter a valid email.' }, 400);
        const ip = req.headers.get('cf-connecting-ip') || 'x';
        if (await tooMany(env, 'wl:' + ip)) return json({ error: 'Too many tries. Please wait a few minutes.' }, 429);
        await note(env, 'wl:' + ip);
        await env.DB.prepare('INSERT OR IGNORE INTO waitlist (product, email, created_at) VALUES (?, ?, ?)').bind(product, email, Date.now()).run();
        return json({ ok: true });
      }
      if (url.pathname.startsWith('/api/admin/') && /^\/api\/admin\/(reviewlink|review\/set|review\/delete|reviewlink\/delete|waitlist\/clear|restore|restore-media)$/.test(url.pathname)) {
        const me = await currentUser(env, req);
        if (!isAdmin(env, me)) return json({ error: 'Owner only.' }, 403);
        const P = url.pathname;
        if (P === '/api/admin/reviewlink') {
          const name = str(body.name, 60).trim();
          if (!name) return json({ error: 'Write the client name first.' }, 400);
          const token = Array.from(crypto.getRandomValues(new Uint8Array(9)), (b) => b.toString(16).padStart(2, '0')).join('');
          await env.DB.prepare('INSERT INTO review_links (token, name, created_at, used) VALUES (?, ?, ?, 0)').bind(token, name, Date.now()).run();
          return json({ token });
        }
        if (P === '/api/admin/review/set') { await env.DB.prepare('UPDATE client_reviews SET approved = ? WHERE id = ?').bind(body.approved ? 1 : 0, Number(body.id) || 0).run(); return json({ ok: true }); }
        if (P === '/api/admin/review/delete') { await env.DB.prepare('DELETE FROM client_reviews WHERE id = ?').bind(Number(body.id) || 0).run(); return json({ ok: true }); }
        if (P === '/api/admin/reviewlink/delete') { await env.DB.prepare('DELETE FROM review_links WHERE token = ?').bind(str(body.token, 40)).run(); return json({ ok: true }); }
        if (P === '/api/admin/waitlist/clear') { await env.DB.prepare('DELETE FROM waitlist WHERE product = ?').bind(str(body.product, 100)).run(); return json({ ok: true }); }
        if (P === '/api/admin/restore-media') {
          const id = String(body.id || ''), mime = String(body.mime || ''), data = String(body.data || '');
          if (!/^[a-f0-9]{8,32}$/.test(id) || !MIMES[mime] || !/^[A-Za-z0-9+/=]+$/.test(data) || data.length < 100 || data.length > 1700000) return json({ error: 'Bad picture.' }, 400);
          const have = await env.DB.prepare('SELECT id FROM media WHERE id = ?').bind(id).first();
          if (have) return json({ ok: true, skipped: true });
          const SZ = 48000, parts = [];
          for (let i = 0; i < data.length; i += SZ) parts.push(data.slice(i, i + SZ));
          const st = [env.DB.prepare('INSERT INTO media (id, mime, n, created_at) VALUES (?, ?, ?, ?)').bind(id, mime, parts.length, Date.now())];
          parts.forEach((q, i) => st.push(env.DB.prepare('INSERT INTO media_chunks (id, i, d) VALUES (?, ?, ?)').bind(id, i, q)));
          await env.DB.batch(st);
          return json({ ok: true });
        }
        if (P === '/api/admin/restore') {
          const lst = (a, n) => (Array.isArray(a) ? a.slice(0, n) : []);
          if (body.site && typeof body.site === 'object') {
            const clean = cleanContent(body.site);
            await env.DB.prepare("INSERT INTO content (k, v, updated_at) VALUES ('site', ?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v, updated_at = excluded.updated_at").bind(JSON.stringify(clean), Date.now()).run();
          }
          const orders = lst(body.orders, 300).map((o) => ({ code: str(o && o.code, 30).trim().toUpperCase(), name: str(o && o.name, 60).trim(), stage: Math.min(5, Math.max(1, parseInt(o && o.stage, 10) || 1)), note: str(o && o.note, 300).trim() })).filter((o) => o.code);
          if (orders.length) await env.DB.prepare("INSERT INTO content (k, v, updated_at) VALUES ('orders', ?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v, updated_at = excluded.updated_at").bind(JSON.stringify(orders), Date.now()).run();
          let n = { subscribers: 0, waitlist: 0, reviews: 0, requests: 0 };
          for (const r of lst(body.subscribers, 5000)) { const e = str(r && r.email, 120).toLowerCase(); if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)) { await env.DB.prepare('INSERT OR IGNORE INTO subscribers (email, created_at) VALUES (?, ?)').bind(e, Number(r.created_at) || Date.now()).run(); n.subscribers++; } }
          for (const r of lst(body.waitlist, 5000)) { const e = str(r && r.email, 120).toLowerCase(), pr = str(r && r.product, 100); if (pr && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)) { await env.DB.prepare('INSERT OR IGNORE INTO waitlist (product, email, created_at) VALUES (?, ?, ?)').bind(pr, e, Number(r.created_at) || Date.now()).run(); n.waitlist++; } }
          for (const r of lst(body.reviews, 300)) { const t = str(r && r.text, 600); if (!t) continue; const ca = Number(r.created_at) || Date.now();
            await env.DB.prepare('INSERT INTO client_reviews (name, stars, text, created_at, approved) SELECT ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM client_reviews WHERE created_at = ? AND text = ?)').bind(str(r.name, 60), Math.min(5, Math.max(1, parseInt(r.stars, 10) || 5)), t, ca, r.approved ? 1 : 0, ca, t).run(); n.reviews++; }
          for (const r of lst(body.requests, 500)) { const t = str(r && r.idea, 2000); if (!t) continue; const ca = Number(r.created_at) || Date.now();
            await env.DB.prepare('INSERT INTO requests (name, contact, kind, size, budget, idea, ref, created_at) SELECT ?, ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM requests WHERE created_at = ? AND idea = ?)').bind(str(r.name, 80), str(r.contact, 120), str(r.kind, 60), str(r.size, 60), str(r.budget, 60), t, str(r.ref, 300), ca, ca, t).run(); n.requests++; }
          return json({ ok: true, ...n });
        }
      }
      if (url.pathname === '/api/subscribe') {
        const email = String(body.email || '').trim().toLowerCase().slice(0, 120);
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json({ error: 'Please enter a valid email.' }, 400);
        const ip = req.headers.get('cf-connecting-ip') || 'x';
        if (await tooMany(env, 'sub:' + ip)) return json({ error: 'Too many tries. Please wait a few minutes.' }, 429);
        await note(env, 'sub:' + ip);
        await env.DB.prepare('INSERT OR IGNORE INTO subscribers (email, created_at) VALUES (?, ?)').bind(email, Date.now()).run();
        return json({ ok: true });
      }
      if (url.pathname === '/api/commission') {
        const name = str(body.name, 80).trim(), contact = str(body.contact, 120).trim(), idea = str(body.idea, 1500).trim();
        if (!name || !contact || !idea) return json({ error: 'Please fill in your name, how to reach you, and your idea.' }, 400);
        const ip = req.headers.get('cf-connecting-ip') || 'x';
        if (await tooMany(env, 'req:' + ip)) return json({ error: 'Too many tries. Please wait a few minutes.' }, 429);
        await note(env, 'req:' + ip);
        await env.DB.prepare('INSERT INTO requests (name, contact, kind, size, budget, idea, ref, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
          .bind(name, contact, str(body.kind, 40), str(body.size, 60), str(body.budget, 60), idea, str(body.ref, 300), Date.now()).run();
        return json({ ok: true });
      }
      if (url.pathname === '/api/hit') {
        const ua = req.headers.get('user-agent') || '';
        if (/bot|crawl|spider|preview|headless|monitor/i.test(ua)) return json({ ok: true });
        const me = await currentUser(env, req);
        if (isAdmin(env, me)) return json({ ok: true });
        const day = new Date().toISOString().slice(0, 10);
        const up = (k) => env.DB.prepare('INSERT INTO hits (day, k, n) VALUES (?, ?, 1) ON CONFLICT(day, k) DO UPDATE SET n = n + 1').bind(day, k).run();
        const wk = String(body.work || '');
        if (wk) { if (WORK.test(wk)) await up('w:' + wk); return json({ ok: true }); }
        await up('v');
        const ip = req.headers.get('cf-connecting-ip') || 'x';
        const hv = (await sha256(ip + '|' + ua + '|' + day)).slice(0, 22);
        const ins = await env.DB.prepare('INSERT OR IGNORE INTO visitors (day, h) VALUES (?, ?)').bind(day, hv).run();
        if (ins.meta && ins.meta.changes > 0) {
          await up('u');
          const cc = String((req.cf && req.cf.country) || '').toUpperCase();
          if (/^[A-Z]{2}$/.test(cc)) await up('c:' + cc);
          try {
            const rh = new URL(String(body.ref || '')).host.slice(0, 60);
            if (rh && rh !== url.host) await up('r:' + rh);
          } catch (e) {}
        }
        return json({ ok: true });
      }
      if (url.pathname === '/api/admin/newsletter') {
        const me = await currentUser(env, req);
        if (!isAdmin(env, me)) return json({ error: 'Owner only.' }, 403);
        if (!(env.RESEND_API_KEY && env.MAIL_FROM)) return json({ error: 'Sending is not set up yet. Use the copy buttons instead.' }, 400);
        const subject = str(body.subject, 150).trim(), text = str(body.body, 5000).trim();
        if (!subject || !text) return json({ error: 'Please write a subject and a message.' }, 400);
        const test = body.test === true;
        let list = test ? [{ email: String(env.ADMIN_EMAIL).trim().toLowerCase() }] : ((await env.DB.prepare('SELECT email FROM subscribers LIMIT 1000').all()).results || []);
        if (!list.length) return json({ error: 'No subscribers yet.' }, 400);
        const origin = url.origin;
        const paras = text.split(/\n{2,}/).map((p) => '<p style="margin:0 0 16px;line-height:1.6">' + escH(p).replace(/\n/g, '<br>') + '</p>').join('');
        let sent = 0, failed = 0;
        for (let i = 0; i < list.length; i += 100) {
          const chunk = list.slice(i, i + 100);
          const mails = [];
          for (const r of chunk) {
            const un = origin + '/api/unsubscribe?e=' + encodeURIComponent(r.email) + '&t=' + (await unsubToken(env, r.email));
            mails.push({ from: env.MAIL_FROM, to: [r.email], subject,
              html: '<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#111">' + paras + '<p><a href="' + origin + '" style="display:inline-block;padding:12px 22px;background:#5b46d6;color:#fff;border-radius:999px;text-decoration:none">Visit my site</a></p><p style="font-size:12px;color:#777;margin-top:30px">ISMAILTENNI ART &middot; <a href="' + un + '" style="color:#777">Unsubscribe</a></p></div>',
              text: text + '\n\n' + origin + '\n\nUnsubscribe: ' + un,
              headers: { 'List-Unsubscribe': '<' + un + '>' } });
          }
          try {
            const rs = await fetch('https://api.resend.com/emails/batch', { method: 'POST', headers: { authorization: 'Bearer ' + env.RESEND_API_KEY, 'content-type': 'application/json' }, body: JSON.stringify(mails) });
            if (rs.ok) sent += chunk.length; else failed += chunk.length;
          } catch (e) { failed += chunk.length; }
        }
        return json({ sent, failed });
      }
      if (url.pathname === '/api/admin/stats') {
        const me = await currentUser(env, req);
        if (!isAdmin(env, me)) return json({ error: 'Owner only.' }, 403);
        const since = new Date(Date.now() - 29 * 86400000).toISOString().slice(0, 10);
        await env.DB.prepare('DELETE FROM visitors WHERE day < ?').bind(since).run();
        const rows = await env.DB.prepare('SELECT day, k, n FROM hits WHERE day >= ?').bind(since).all();
        const perDay = {}, countries = {}, refs = {}, works = {};
        let views = 0, uniques = 0;
        (rows.results || []).forEach((r) => {
          const d = (perDay[r.day] = perDay[r.day] || { v: 0, u: 0 });
          if (r.k === 'v') { d.v += r.n; views += r.n; }
          else if (r.k === 'u') { d.u += r.n; uniques += r.n; }
          else if (r.k.startsWith('c:')) countries[r.k.slice(2)] = (countries[r.k.slice(2)] || 0) + r.n;
          else if (r.k.startsWith('r:')) refs[r.k.slice(2)] = (refs[r.k.slice(2)] || 0) + r.n;
          else if (r.k.startsWith('w:')) works[r.k.slice(2)] = (works[r.k.slice(2)] || 0) + r.n;
        });
        const top = (o) => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, 8);
        const days = [];
        for (let i = 29; i >= 0; i--) { const dd = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10); days.push({ day: dd, v: (perDay[dd] || {}).v || 0, u: (perDay[dd] || {}).u || 0 }); }
        const one = async (q) => { const r = await env.DB.prepare(q).first(); return r ? r.n : 0; };
        const lk = await env.DB.prepare('SELECT work_id AS id, COUNT(*) AS n FROM likes GROUP BY work_id ORDER BY n DESC LIMIT 8').all();
        return json({ views, uniques, days, countries: top(countries), refs: top(refs), works: top(works),
          loved: (lk.results || []).map((r) => [r.id, r.n]),
          members: await one('SELECT COUNT(*) AS n FROM users'), subscribers: await one('SELECT COUNT(*) AS n FROM subscribers'),
          requests: await one('SELECT COUNT(*) AS n FROM requests'), comments: await one('SELECT COUNT(*) AS n FROM comments') });
      }
      if (url.pathname === '/api/admin/orders') {
        const me = await currentUser(env, req);
        if (!isAdmin(env, me)) return json({ error: 'Owner only.' }, 403);
        const list = (Array.isArray(body.orders) ? body.orders : []).slice(0, 300).map((o) => ({
          code: str(o && o.code, 30).trim().toUpperCase(), name: str(o && o.name, 60).trim(),
          stage: Math.min(5, Math.max(1, parseInt(o && o.stage, 10) || 1)), note: str(o && o.note, 300).trim(),
        })).filter((o) => o.code);
        await env.DB.prepare("INSERT INTO content (k, v, updated_at) VALUES ('orders', ?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v, updated_at = excluded.updated_at")
          .bind(JSON.stringify(list), Date.now()).run();
        return json({ ok: true, n: list.length });
      }
      if (url.pathname === '/api/admin/request/delete') {
        const me = await currentUser(env, req);
        if (!isAdmin(env, me)) return json({ error: 'Owner only.' }, 403);
        await env.DB.prepare('DELETE FROM requests WHERE id = ?').bind(Number(body.id) || 0).run();
        return json({ ok: true });
      }
      if (url.pathname === '/api/admin/upload') {
        const me = await currentUser(env, req);
        if (!isAdmin(env, me)) return json({ error: 'Owner only.' }, 403);
        const mime = String(body.mime || '');
        const data = String(body.data || '');
        if (!MIMES[mime] || !/^[A-Za-z0-9+/=]+$/.test(data) || data.length < 100 || data.length > 1700000)
          return json({ error: 'That picture is too big or not a photo. Try a smaller one.' }, 400);
        const id = Array.from(crypto.getRandomValues(new Uint8Array(8)), (b) => b.toString(16).padStart(2, '0')).join('');
        const SZ = 48000, parts = [];
        for (let i = 0; i < data.length; i += SZ) parts.push(data.slice(i, i + SZ));
        const st = [env.DB.prepare('INSERT INTO media (id, mime, n, created_at) VALUES (?, ?, ?, ?)').bind(id, mime, parts.length, Date.now())];
        parts.forEach((p, i) => st.push(env.DB.prepare('INSERT INTO media_chunks (id, i, d) VALUES (?, ?, ?)').bind(id, i, p)));
        await env.DB.batch(st);
        return json({ url: '/api/media/' + id });
      }
      if (url.pathname === '/api/admin/content') {
        const me = await currentUser(env, req);
        if (!isAdmin(env, me)) return json({ error: 'Owner only.' }, 403);
        const clean = cleanContent(body);
        await env.DB.prepare("INSERT INTO content (k, v, updated_at) VALUES ('site', ?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v, updated_at = excluded.updated_at")
          .bind(JSON.stringify(clean), Date.now()).run();
        // remove uploaded pictures that are no longer used (keep anything newer than 1 hour)
        const keep = mediaIds(clean);
        const all = await env.DB.prepare('SELECT id FROM media WHERE created_at < ?').bind(Date.now() - 3600 * 1000).all();
        const gone = (all.results || []).map((r) => r.id).filter((x) => !keep.has(x));
        for (const g of gone.slice(0, 40)) {
          await env.DB.batch([env.DB.prepare('DELETE FROM media_chunks WHERE id = ?').bind(g), env.DB.prepare('DELETE FROM media WHERE id = ?').bind(g)]);
        }
        return json({ ok: true, works: clean.works.length, photos: clean.photos.length, films: clean.films.length, texts: Object.keys(clean.texts).length });
      }
      if (url.pathname === '/api/logout') {
        const t = getCookie(req, 'session');
        if (t) await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256(t)).run();
        return json({ ok: true }, 200, { 'set-cookie': sessionCookie('', 0) });
      }
      return json({ error: 'Not found' }, 404);
    } catch (e) {
      return json({ error: 'Something went wrong. Please try again.' }, 500);
    }
  },
};

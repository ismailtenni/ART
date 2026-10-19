// ISMAILTENNI ART - accounts (sign up / log in) on Cloudflare Pages + D1.
// Needs a D1 database bound to this project with the variable name: DB
const enc = new TextEncoder();
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
async function note(env, key) {
  await env.DB.prepare('INSERT INTO attempts (key, at) VALUES (?, ?)').bind(key, Date.now()).run();
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(req);
    if (!env.DB) return json({ error: 'The database is not connected yet.' }, 503);
    try {
      if (url.pathname === '/api/me' && req.method === 'GET') {
        const u = await currentUser(env, req);
        return json({ user: u ? { name: u.name, email: u.email } : null });
      }
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

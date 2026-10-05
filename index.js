import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import pg from 'pg';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const E = process.env;
const missing = ['DATABASE_URL', 'JWT_SECRET', 'ADMIN_SALT', 'ADMIN_HASH'].filter(k => !E[k]);
if (missing.length || E.JWT_SECRET.length < 32) { console.error('Configuration incomplète : ' + (missing.join(', ') || 'JWT_SECRET trop court')); process.exit(1); }
const prod = E.NODE_ENV === 'production';
const ORIGINS = (E.FRONTEND_ORIGIN || '').split(',').map(s => s.trim().replace(/\/+$/, '')).filter(s => (prod ? /^https:\/\/[\w.:-]+$/ : /^https?:\/\/[\w.:-]+$/).test(s));
if (prod && !ORIGINS.length) console.warn('FRONTEND_ORIGIN absent ou invalide : les actions depuis le site seront refusées');
if (E.PAYPAL_ENV && !['sandbox', 'live'].includes(E.PAYPAL_ENV)) { console.error('PAYPAL_ENV doit valoir sandbox ou live'); process.exit(1); }
const WH = E.PAYPAL_WEBHOOK_ID && E.PAYPAL_WEBHOOK_ID !== 'A_DEFINIR' ? E.PAYPAL_WEBHOOK_ID : '';
const ID = /^[a-f0-9]{16}$/;
const STATUSES = ['En attente de paiement', 'Paiement à vérifier', 'Payée', 'Payée - stock à vérifier', 'Nouvelle', 'Confirmée', 'Expédiée', 'Livrée', 'Annulée', 'Remboursée', 'Paiement refusé'];
const pool = new pg.Pool({ connectionString: E.DATABASE_URL, max: 5, ssl: prod ? { rejectUnauthorized: false } : undefined });
pool.on('error', e => console.error('Connexion base :', e.code || 'erreur'));
process.on('unhandledRejection', e => console.error('Erreur asynchrone :', e?.code || e?.message));
process.on('uncaughtException', e => { console.error('Erreur fatale :', e?.code || e?.message); process.exit(1); });
try { await pool.query('select 1'); } catch (e) { console.error('Base de données inaccessible :', e.code || 'erreur de connexion'); process.exit(1); }
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const wrap = fn => (req, res, next) => fn(req, res).catch(next);
const str = (v, n) => (typeof v === 'string' ? v.trim().slice(0, n) : '');
const uid = () => crypto.randomBytes(8).toString('hex');
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const tx = async fn => {
  const c = await pool.connect();
  try { await c.query('begin'); const r = await fn(c); await c.query('commit'); return r; }
  catch (e) { await c.query('rollback').catch(() => {}); throw e; }
  finally { c.release(); }
};

await pool.query(`
create table if not exists kv (k text primary key, v jsonb not null);
create table if not exists files (name text primary key, mime text not null, data bytea not null);
create table if not exists products (id text primary key, name text not null, category text not null, description text not null default '', price integer not null check (price >= 0), stock integer not null check (stock >= 0), sizes text[] not null default '{}', image text not null default '', featured boolean not null default false, created_at bigint not null);
create table if not exists orders (id text primary key, number text unique not null, name text not null, phone text not null, city text not null, address text not null, note text not null default '', payment text not null, status text not null, total integer not null, pp_id text unique, capture_id text, idem_key text unique, payload_hash text, created_at bigint not null);
create table if not exists order_items (order_id text not null references orders(id) on delete cascade, product_id text not null, name text not null, size text not null default '', qty integer not null, price integer not null);
create table if not exists webhook_events (id text primary key, type text, received_at bigint not null);`);

const old = (await pool.query("select v from kv where k = 'db'")).rows[0];
if (old && !(await pool.query('select 1 from products limit 1')).rowCount) await tx(async c => {
  for (const p of old.v.products || []) await c.query('insert into products values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) on conflict do nothing', [p.id, p.name, p.category, p.description || '', p.price, p.stock, p.sizes || [], p.image || '', !!p.featured, p.createdAt || Date.now()]);
  for (const o of old.v.orders || []) {
    await c.query('insert into orders (id, number, name, phone, city, address, note, payment, status, total, pp_id, capture_id, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) on conflict do nothing', [o.id, o.number, o.name, o.phone, o.city, o.address, o.note || '', o.payment, o.status, o.total, o.ppId || null, o.captureId || null, o.createdAt]);
    for (const i of o.items || []) await c.query('insert into order_items values ($1,$2,$3,$4,$5,$6)', [o.id, i.id, i.name, i.size || '', i.qty, i.price]);
  }
  await c.query("update kv set k = 'db_migrated' where k = 'db'");
});

const PP = { id: E.PAYPAL_CLIENT_ID, secret: E.PAYPAL_SECRET, cur: E.PAYPAL_CURRENCY || 'EUR', rate: Number(E.RATE_AR_PER_UNIT), base: E.PAYPAL_ENV === 'live' ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com' };
const ppOn = !!(PP.id && PP.secret && PP.rate > 0);
if (ppOn && E.PAYPAL_ENV === 'live' && !WH) { console.error('Mode live : PAYPAL_WEBHOOK_ID est obligatoire'); process.exit(1); }
if (ppOn && E.PAYPAL_ENV === 'live' && E.PAYPAL_LIVE_CONFIRM !== 'oui') { console.error('Mode live non confirmé : définissez PAYPAL_LIVE_CONFIRM=oui'); process.exit(1); }
console.log('PayPal :', ppOn ? (E.PAYPAL_ENV || 'sandbox') : 'désactivé', '| Webhook :', WH ? 'configuré' : 'non configuré');
const toCur = ar => (Math.round(ar / PP.rate * 100) / 100).toFixed(2);
let tok = { v: '', exp: 0 };
const ppCall = async (url, body, reqId) => {
  try {
    if (tok.exp < Date.now() + 60e3) {
      const t = await fetch(PP.base + '/v1/oauth2/token', { method: 'POST', headers: { Authorization: 'Basic ' + Buffer.from(PP.id + ':' + PP.secret).toString('base64'), 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'grant_type=client_credentials' });
      if (!t.ok) throw new Error('auth ' + t.status);
      const d = await t.json(); tok = { v: d.access_token, exp: Date.now() + d.expires_in * 1000 };
    }
    const h = { Authorization: 'Bearer ' + tok.v, 'Content-Type': 'application/json' }; if (reqId) h['PayPal-Request-Id'] = reqId;
    const r = await fetch(PP.base + url, { method: 'POST', headers: h, body: body ? (typeof body === 'string' ? body : JSON.stringify(body)) : undefined });
    if (!r.ok) throw new Error('paypal ' + r.status);
    return await r.json();
  } catch (e) { console.error('PayPal', e.message); throw new HttpError(502, 'Service de paiement indisponible'); }
};

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', Number(E.TRUST_PROXY || 1));
app.use('/backend', (req, _res, next) => { req.url = '/api' + req.url; next(); });
const PPH = ['https://*.paypal.com', 'https://*.paypalobjects.com'];
app.use(helmet({ crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' }, contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'", ...PPH], frameSrc: PPH, connectSrc: ["'self'", ...PPH], styleSrc: ["'self'", "'unsafe-inline'"],
  imgSrc: ["'self'", 'data:', ...PPH], objectSrc: ["'none'"], frameAncestors: ["'none'"], baseUri: ["'self'"], formAction: ["'self'"] } } }));
app.use(express.json({ limit: '64kb', verify: (req, _res, buf) => { if (req.originalUrl.startsWith('/api/paypal/webhook')) req.raw = buf; } }));
app.use('/api', rateLimit({ windowMs: 15 * 60e3, limit: 300 }));
app.use('/api', (req, res, next) => {
  const o = req.get('origin');
  if (o) {
    let same = false; try { same = new URL(o).host === req.get('host'); } catch {}
    const allowed = ORIGINS.includes(o);
    if (!same && !allowed && req.method !== 'GET') return res.status(403).json({ error: 'Origine refusée' });
    if (allowed) {
      res.set({ 'Access-Control-Allow-Origin': o, 'Access-Control-Allow-Credentials': 'true', 'Access-Control-Allow-Headers': 'Content-Type, X-CSRF-Token, Idempotency-Key', 'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE', Vary: 'Origin' });
      if (req.method === 'OPTIONS') return res.sendStatus(204);
    }
  }
  next();
});

const cname = prod ? '__Host-adm' : 'adm';
const cookie = (req, n) => (req.get('cookie') || '').split(';').map(c => c.trim().split('=')).find(c => c[0] === n)?.[1];
const JWT_OPT = { algorithms: ['HS256'], issuer: 'boutique', audience: 'admin' };
const admin = (req, res, next) => {
  let t; try { t = jwt.verify(cookie(req, cname) || '', E.JWT_SECRET, JWT_OPT); } catch { return res.status(401).json({ error: 'Non autorisé' }); }
  if (req.method !== 'GET') {
    const a = Buffer.from(req.get('x-csrf-token') || ''), b = Buffer.from(t.csrf || '');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(403).json({ error: 'Jeton de sécurité invalide' });
  }
  req.admin = t; next();
};
app.use('/api/admin', rateLimit({ windowMs: 15 * 60e3, limit: 200 }));
app.post('/api/admin/login', rateLimit({ windowMs: 15 * 60e3, limit: 5, skipSuccessfulRequests: true }), (req, res) => {
  const given = crypto.scryptSync(str(req.body?.password, 200), E.ADMIN_SALT, 64);
  if (!crypto.timingSafeEqual(given, Buffer.from(E.ADMIN_HASH, 'hex'))) return res.status(401).json({ error: 'Mot de passe incorrect' });
  const csrf = crypto.randomBytes(24).toString('hex');
  const token = jwt.sign({ csrf }, E.JWT_SECRET, { algorithm: 'HS256', expiresIn: '2h', issuer: 'boutique', audience: 'admin', subject: 'admin' });
  res.cookie(cname, token, { httpOnly: true, secure: prod, sameSite: 'strict', maxAge: 2 * 3600e3, path: '/' });
  res.json({ csrf });
});
app.post('/api/admin/logout', (req, res) => { res.clearCookie(cname, { path: '/', httpOnly: true, secure: prod, sameSite: 'strict' }); res.json({ ok: true }); });
app.get('/api/admin/me', admin, (req, res) => res.json({ csrf: req.admin.csrf }));

const cleanProduct = b => {
  b = b || {};
  const p = { name: str(b.name, 120), category: str(b.category, 40), description: str(b.description, 2000), price: Number(b.price), stock: Number(b.stock),
    sizes: (Array.isArray(b.sizes) ? b.sizes : []).map(s => str(s, 10)).filter(s => /^[\w .\/-]{1,10}$/.test(s)).slice(0, 12),
    image: /^\/uploads\/[a-f0-9]{16}\.(jpg|png|webp)$/.test(b.image) ? b.image : '', featured: b.featured === true };
  if (!p.name || !p.category || !Number.isInteger(p.price) || p.price < 0 || p.price > 1e8 || !Number.isInteger(p.stock) || p.stock < 0 || p.stock > 1e5) throw new HttpError(400, 'Données invalides');
  return p;
};
const pub = r => ({ id: r.id, name: r.name, category: r.category, description: r.description, price: r.price, stock: r.stock, sizes: r.sizes, image: r.image, featured: r.featured });
app.get('/api/health', wrap(async (req, res) => { await pool.query('select 1'); res.json({ ok: true }); }));
app.get('/api/products', wrap(async (req, res) => res.json((await pool.query('select * from products order by created_at desc')).rows.map(pub))));
app.get('/api/products/:id', wrap(async (req, res) => {
  const r = ID.test(req.params.id) && (await pool.query('select * from products where id = $1', [req.params.id])).rows[0];
  if (!r) throw new HttpError(404, 'Produit introuvable'); res.json(pub(r));
}));
const pv = p => [p.name, p.category, p.description, p.price, p.stock, p.sizes, p.image, p.featured];
app.post('/api/admin/products', admin, wrap(async (req, res) => {
  const p = cleanProduct(req.body);
  const r = await pool.query('insert into products (id, name, category, description, price, stock, sizes, image, featured, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) returning *', [uid(), ...pv(p), Date.now()]);
  res.json(pub(r.rows[0]));
}));
app.put('/api/admin/products/:id', admin, wrap(async (req, res) => {
  const p = cleanProduct(req.body);
  const r = ID.test(req.params.id) && await pool.query('update products set name=$2, category=$3, description=$4, price=$5, stock=$6, sizes=$7, image=$8, featured=$9 where id=$1 returning *', [req.params.id, ...pv(p)]);
  if (!r?.rowCount) throw new HttpError(404, 'Introuvable'); res.json(pub(r.rows[0]));
}));
app.delete('/api/admin/products/:id', admin, wrap(async (req, res) => {
  if (ID.test(req.params.id)) await pool.query('delete from products where id = $1', [req.params.id]); res.json({ ok: true });
}));

const mimes = { jpg: 'image/jpeg', png: 'image/png', webp: 'image/webp' };
const sniff = b => b.length < 16 ? null : (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) ? 'jpg'
  : b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) ? 'png'
  : (b.subarray(0, 4).toString('latin1') === 'RIFF' && b.subarray(8, 12).toString('latin1') === 'WEBP') ? 'webp' : null;
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 3 * 1024 * 1024, files: 1, fields: 0 } });
app.post('/api/admin/upload', rateLimit({ windowMs: 3600e3, limit: 60 }), admin, upload.single('image'), wrap(async (req, res) => {
  const f = req.file; if (!f) throw new HttpError(400, 'Fichier manquant');
  const ext = sniff(f.buffer);
  const claimed = path.extname(f.originalname || '').slice(1).toLowerCase().replace('jpeg', 'jpg');
  if (!ext || mimes[ext] !== f.mimetype || (claimed && claimed !== ext) || /<\s*(script|\?php|html|svg|iframe)/i.test(f.buffer.toString('latin1'))) throw new HttpError(400, 'Fichier refusé : JPG, PNG ou WEBP uniquement');
  const name = crypto.randomBytes(8).toString('hex') + '.' + ext;
  await pool.query('insert into files (name, mime, data) values ($1, $2, $3)', [name, mimes[ext], f.buffer]);
  res.json({ image: '/uploads/' + name });
}));
app.get('/uploads/:name', wrap(async (req, res) => {
  const r = /^[a-f0-9]{16}\.(jpg|png|webp)$/.test(req.params.name) && (await pool.query('select mime, data from files where name = $1', [req.params.name])).rows[0];
  if (!r) return res.sendStatus(404);
  res.set({ 'Content-Type': r.mime, 'Cache-Control': 'public, max-age=604800, immutable', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'; sandbox", 'Content-Disposition': 'inline' }).send(r.data);
}));

const customer = b => {
  const c = { name: str(b.name, 100), phone: str(b.phone, 25), city: str(b.city, 80), address: str(b.address, 250), note: str(b.note, 500) };
  if (!c.name || !/^[0-9+ ]{8,25}$/.test(c.phone) || !c.city || !c.address) throw new HttpError(400, 'Informations de livraison invalides');
  return c;
};
async function priceCart(c, items, lock) {
  const ids = [...new Set(items.map(i => String(i?.id)))];
  if (ids.some(i => !ID.test(i))) throw new HttpError(400, 'Panier invalide');
  const rows = (await c.query('select * from products where id = any($1)' + (lock ? ' order by id for update' : ''), [ids])).rows;
  const by = new Map(rows.map(r => [r.id, r])), used = new Map(), lines = []; let total = 0;
  for (const it of items) {
    const p = by.get(it.id), qty = Number(it.qty);
    if (!p || !Number.isInteger(qty) || qty < 1 || qty > 20) throw new HttpError(400, 'Article invalide');
    const size = str(it.size, 10); if (p.sizes.length && !p.sizes.includes(size)) throw new HttpError(400, 'Taille invalide');
    used.set(p.id, (used.get(p.id) || 0) + qty);
    if (used.get(p.id) > p.stock) throw new HttpError(409, 'Stock insuffisant : ' + p.name);
    lines.push({ id: p.id, name: p.name, size, qty, price: p.price }); total += p.price * qty;
  }
  if (total > 2e9) throw new HttpError(400, 'Montant trop élevé');
  return { lines, total };
}
async function createOrder(req, kind, retry = true) {
  const key = req.get('idempotency-key') || '';
  if (!/^[\w-]{16,64}$/.test(key)) throw new HttpError(400, 'Requête invalide');
  const b = req.body || {}, cu = customer(b);
  if (!Array.isArray(b.items) || !b.items.length || b.items.length > 30) throw new HttpError(400, 'Panier invalide');
  const hash = sha(JSON.stringify([kind, cu, b.items.map(i => [String(i?.id), str(i?.size, 10), Number(i?.qty)])]));
  try {
    return await tx(async c => {
      const ex = (await c.query('select id, number, total, pp_id, status, payload_hash from orders where idem_key = $1', [key])).rows[0];
      if (ex) { if (ex.payload_hash !== hash) throw new HttpError(409, 'Requête déjà utilisée'); return ex; }
      const cash = kind === 'cash', { lines, total } = await priceCart(c, b.items, cash);
      const o = { id: uid(), number: 'CMD-' + Date.now().toString(36).toUpperCase() + crypto.randomBytes(2).toString('hex').toUpperCase(), total, pp_id: null };
      await c.query('insert into orders (id, number, name, phone, city, address, note, payment, status, total, idem_key, payload_hash, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)',
        [o.id, o.number, cu.name, cu.phone, cu.city, cu.address, cu.note, cash ? 'Paiement à la livraison' : 'PayPal', cash ? 'Nouvelle' : 'En attente de paiement', total, key, hash, Date.now()]);
      for (const l of lines) {
        await c.query('insert into order_items values ($1,$2,$3,$4,$5,$6)', [o.id, l.id, l.name, l.size, l.qty, l.price]);
        if (cash) await c.query('update products set stock = stock - $1 where id = $2', [l.qty, l.id]);
      }
      return o;
    });
  } catch (e) { if (e.code === '23505' && retry) return createOrder(req, kind, false); throw e; }
}
async function markPaid(orderId, cap) {
  return tx(async c => {
    const o = (await c.query('select * from orders where id = $1 for update', [orderId])).rows[0];
    if (!o) throw new HttpError(404, 'Commande introuvable');
    if (o.status.startsWith('Payée') || ['Expédiée', 'Livrée', 'Confirmée'].includes(o.status)) return o;
    if (cap.status !== 'COMPLETED' || cap.amount?.currency_code !== PP.cur || cap.amount?.value !== toCur(o.total)) {
      await c.query("update orders set status = 'Paiement à vérifier' where id = $1", [o.id]); return { ...o, bad: true };
    }
    const items = (await c.query('select product_id, qty from order_items where order_id = $1', [o.id])).rows;
    const stock = new Map((await c.query('select id, stock from products where id = any($1) order by id for update', [items.map(i => i.product_id)])).rows.map(r => [r.id, r.stock]));
    const ok = items.every(i => (stock.get(i.product_id) ?? 0) >= i.qty);
    if (ok) for (const i of items) await c.query('update products set stock = stock - $1 where id = $2', [i.qty, i.product_id]);
    const st = ok ? 'Payée' : 'Payée - stock à vérifier';
    await c.query('update orders set status = $1, capture_id = $2 where id = $3', [st, str(cap.id, 40), o.id]);
    return { ...o, status: st };
  });
}

const orderLimit = rateLimit({ windowMs: 3600e3, limit: 15 });
app.get('/api/config', (req, res) => res.json({ paypal: ppOn ? { clientId: PP.id, currency: PP.cur, rate: PP.rate } : null }));
app.post('/api/orders', orderLimit, wrap(async (req, res) => { const o = await createOrder(req, 'cash'); res.json({ number: o.number, total: o.total }); }));
app.post('/api/paypal/create', orderLimit, wrap(async (req, res) => {
  if (!ppOn) throw new HttpError(503, 'Paiement en ligne indisponible');
  const o = await createOrder(req, 'paypal');
  if (o.pp_id) return res.json({ id: o.pp_id });
  const pp = await ppCall('/v2/checkout/orders', { intent: 'CAPTURE', purchase_units: [{ reference_id: o.id, custom_id: o.id, amount: { currency_code: PP.cur, value: toCur(o.total) } }] }, 'create-' + o.id);
  await pool.query('update orders set pp_id = $1 where id = $2 and pp_id is null', [pp.id, o.id]);
  res.json({ id: pp.id });
}));
app.post('/api/paypal/capture', orderLimit, wrap(async (req, res) => {
  const id = str(req.body?.id, 40);
  const row = (await pool.query('select id, number, total, status from orders where pp_id = $1', [id])).rows[0];
  if (!row) throw new HttpError(404, 'Commande introuvable');
  if (row.status.startsWith('Payée')) return res.json({ number: row.number, total: row.total });
  const d = await ppCall('/v2/checkout/orders/' + encodeURIComponent(id) + '/capture', null, 'capture-' + row.id);
  const cap = d.purchase_units?.[0]?.payments?.captures?.[0];
  if (!cap) throw new HttpError(402, 'Paiement non validé, contactez-nous');
  const r = await markPaid(row.id, cap);
  if (r.bad) throw new HttpError(402, 'Paiement non validé, contactez-nous');
  res.json({ number: r.number, total: r.total });
}));
app.post('/api/paypal/webhook', rateLimit({ windowMs: 60e3, limit: 60 }), wrap(async (req, res) => {
  if (!ppOn || !WH || !req.raw) return res.sendStatus(503);
  const h = n => JSON.stringify(req.get(n) || '');
  const v = await ppCall('/v1/notifications/verify-webhook-signature', `{"auth_algo":${h('paypal-auth-algo')},"cert_url":${h('paypal-cert-url')},"transmission_id":${h('paypal-transmission-id')},"transmission_sig":${h('paypal-transmission-sig')},"transmission_time":${h('paypal-transmission-time')},"webhook_id":${JSON.stringify(WH)},"webhook_event":${req.raw.toString('utf8')}}`);
  if (v.verification_status !== 'SUCCESS') return res.sendStatus(401);
  const ev = req.body, evId = str(ev?.id, 60);
  if (!evId || (await pool.query('select 1 from webhook_events where id = $1', [evId])).rowCount) return res.sendStatus(200);
  const cap = ev.resource, oid = str(cap?.custom_id, 20);
  if (ID.test(oid)) try {
    if (ev.event_type === 'PAYMENT.CAPTURE.COMPLETED') await markPaid(oid, cap);
    else if (ev.event_type === 'PAYMENT.CAPTURE.DENIED') await pool.query("update orders set status = 'Paiement refusé' where id = $1 and status not like 'Payée%'", [oid]);
    else if (['PAYMENT.CAPTURE.REFUNDED', 'PAYMENT.CAPTURE.REVERSED'].includes(ev.event_type)) await pool.query("update orders set status = 'Remboursée' where id = $1", [oid]);
  } catch (e) { if (!(e instanceof HttpError)) throw e; }
  await pool.query('insert into webhook_events values ($1, $2, $3) on conflict do nothing', [evId, str(ev.event_type, 60), Date.now()]);
  res.sendStatus(200);
}));

app.get('/api/admin/orders', admin, wrap(async (req, res) => {
  const r = await pool.query(`select o.id, o.number, o.name, o.phone, o.city, o.address, o.note, o.payment, o.status, o.total, o.created_at,
    coalesce(json_agg(json_build_object('name', i.name, 'size', i.size, 'qty', i.qty, 'price', i.price)) filter (where i.order_id is not null), '[]') as items
    from orders o left join order_items i on i.order_id = o.id group by o.id order by o.created_at desc limit 500`);
  res.json(r.rows.map(({ created_at, ...o }) => ({ ...o, createdAt: Number(created_at) })));
}));
app.patch('/api/admin/orders/:id', admin, wrap(async (req, res) => {
  const s = str(req.body?.status, 30);
  if (!ID.test(req.params.id) || !STATUSES.includes(s)) throw new HttpError(400, 'Invalide');
  const r = await pool.query('update orders set status = $1 where id = $2', [s, req.params.id]);
  if (!r.rowCount) throw new HttpError(404, 'Introuvable'); res.json({ ok: true });
}));
app.use('/api', (req, res) => res.status(404).json({ error: 'Introuvable' }));

const dist = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'client', 'dist');
if (fs.existsSync(dist)) { app.use(express.static(dist)); app.get('*', (req, res) => res.sendFile(path.join(dist, 'index.html'))); }
app.use((err, req, res, next) => {
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
  if (err.type === 'entity.parse.failed' || err.type === 'entity.too.large' || err.name === 'MulterError') return res.status(err.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'Photo trop lourde (3 Mo max)' : 'Requête invalide' });
  console.error('Erreur', req.method, req.path, err.code || err.message);
  res.status(500).json({ error: 'Erreur serveur' });
});
app.listen(E.PORT || 3000, () => console.log('Serveur prêt'));

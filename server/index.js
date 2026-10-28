import express from 'express';
import multer from 'multer';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdirSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const dataDir = path.join(here, 'data');
const uploadDir = path.join(here, 'uploads');
mkdirSync(dataDir, { recursive: true });
mkdirSync(uploadDir, { recursive: true });

const db = new Database(path.join(dataDir, 'propertyplug101.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS properties (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    type TEXT NOT NULL,
    deal TEXT NOT NULL,
    price INTEGER,
    address TEXT NOT NULL,
    area TEXT NOT NULL,
    contact_name TEXT NOT NULL,
    contact_email TEXT NOT NULL,
    contact_phone TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    photos TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'published',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS enquiries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL,
    area TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));
app.use('/uploads', express.static(uploadDir, { maxAge: '1d', immutable: false }));
const sessionDays = 7;
const hashToken = token => createHash('sha256').update(token).digest('hex');
const setSessionCookie = (res, token) => {
  const parts = [`pp_session=${token}`, 'HttpOnly', 'SameSite=Strict', 'Path=/', `Max-Age=${sessionDays * 86400}`];
  if (process.env.NODE_ENV === 'production') parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
};
const clearSessionCookie = res => res.setHeader('Set-Cookie', 'pp_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
function readCookie(req, name) {
  const item = (req.headers.cookie || '').split(';').map(value => value.trim()).find(value => value.startsWith(`${name}=`));
  return item ? decodeURIComponent(item.slice(name.length + 1)) : null;
}
function currentUser(req, _res, next) {
  const token = readCookie(req, 'pp_session');
  if (!token) return next();
  const session = db.prepare(`SELECT users.id, users.name, users.email, sessions.token_hash
    FROM sessions JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > ?`).get(hashToken(token), Date.now());
  if (session) req.user = { id: session.id, name: session.name, email: session.email };
  next();
}
app.use('/api', currentUser);
function requireUser(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Please log in to continue.' });
  next();
}
function createSession(userId, res) {
  const token = randomBytes(32).toString('base64url');
  const expiresAt = Date.now() + sessionDays * 86400 * 1000;
  db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)').run(hashToken(token), userId, expiresAt);
  setSessionCookie(res, token);
}

app.get('/api/health', (_req, res) => res.json({ ok: true }));
app.get('/api/auth/me', (req, res) => res.json({ user: req.user || null }));
app.post('/api/auth/register', async (req, res) => {
  const name = String(req.body?.name || '').trim();
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  if (name.length < 2 || name.length > 100 || !/^\S+@\S+\.\S+$/.test(email) || password.length < 8 || password.length > 200) {
    return res.status(400).json({ error: 'Enter a name, a valid email, and a password with at least 8 characters.' });
  }
  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) return res.status(409).json({ error: 'An account with that email already exists.' });
  const passwordHash = await bcrypt.hash(password, 12);
  const result = db.prepare('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)').run(name, email, passwordHash);
  createSession(Number(result.lastInsertRowid), res);
  res.status(201).json({ user: { id: Number(result.lastInsertRowid), name, email } });
});
app.post('/api/auth/login', async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  const user = db.prepare('SELECT id, name, email, password_hash FROM users WHERE email = ?').get(email);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Email or password is incorrect.' });
  createSession(user.id, res);
  res.json({ user: { id: user.id, name: user.name, email: user.email } });
});
app.post('/api/auth/logout', (req, res) => {
  const token = readCookie(req, 'pp_session');
  if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashToken(token));
  clearSessionCookie(res);
  res.json({ ok: true });
});

const allowedTypes = new Set(['House', 'Apartment', 'Townhouse', 'Land', 'Commercial']);
const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, uploadDir),
    filename: (_req, file, cb) => cb(null, `${randomUUID()}${path.extname(file.originalname).toLowerCase()}`)
  }),
  limits: { fileSize: 8 * 1024 * 1024, files: 5, fields: 12, parts: 18 },
  fileFilter: (_req, file, cb) => {
    if (!['image/jpeg', 'image/png', 'image/webp'].includes(file.mimetype)) return cb(new Error('Upload JPG, PNG, or WebP images only.'));
    cb(null, true);
  }
});
function propertyResponse(row) {
  return { ...row, photos: JSON.parse(row.photos), price: row.price === null ? null : Number(row.price) };
}
app.get('/api/properties', (_req, res) => {
  const rows = db.prepare(`SELECT id, user_id AS userId, type, deal, price, address, area, description, photos, status, created_at AS createdAt
    FROM properties WHERE status = 'published' ORDER BY id DESC`).all();
  res.json({ properties: rows.map(propertyResponse) });
});
app.get('/api/my/properties', requireUser, (req, res) => {
  const rows = db.prepare(`SELECT id, user_id AS userId, type, deal, price, address, area, description, photos, status, created_at AS createdAt
    FROM properties WHERE user_id = ? ORDER BY id DESC`).all(req.user.id);
  res.json({ properties: rows.map(propertyResponse) });
});
app.post('/api/properties', requireUser, upload.array('photos', 5), (req, res) => {
  const type = String(req.body.propertyType || '');
  const dealValue = String(req.body.dealType || 'Sell');
  const deal = dealValue === 'Rent out' ? 'Rent' : 'Buy';
  const address = String(req.body.address || '').trim();
  const area = String(req.body.area || '').trim();
  const contactName = String(req.body.name || '').trim();
  const contactEmail = String(req.body.email || '').trim().toLowerCase();
  const contactPhone = String(req.body.phone || '').trim();
  const description = String(req.body.notes || '').trim().slice(0, 2000);
  const rawPrice = String(req.body.price || '').trim();
  const price = rawPrice ? Number(rawPrice) : null;
  if (!allowedTypes.has(type) || address.length < 3 || address.length > 200 || area.length < 2 || area.length > 160 || contactName.length < 2 || !/^\S+@\S+\.\S+$/.test(contactEmail) || contactPhone.length < 5 || contactPhone.length > 40 || (price !== null && (!Number.isSafeInteger(price) || price < 1))) {
    return res.status(400).json({ error: 'Check the property type, address, area, contact details, and asking price.' });
  }
  const photos = (req.files || []).map(file => `/uploads/${file.filename}`);
  if (!photos.length) return res.status(400).json({ error: 'Add at least one property photo.' });
  const result = db.prepare(`INSERT INTO properties (user_id, type, deal, price, address, area, contact_name, contact_email, contact_phone, description, photos)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(req.user.id, type, deal, price, address, area, contactName, contactEmail, contactPhone, description, JSON.stringify(photos));
  const row = db.prepare(`SELECT id, user_id AS userId, type, deal, price, address, area, description, photos, status, created_at AS createdAt FROM properties WHERE id = ?`).get(Number(result.lastInsertRowid));
  res.status(201).json({ property: propertyResponse(row) });
});
app.post('/api/enquiries', (req, res) => {
  const name = String(req.body?.name || '').trim();
  const email = String(req.body?.email || '').trim().toLowerCase();
  const phone = String(req.body?.phone || '').trim();
  const area = String(req.body?.area || '').trim();
  const message = String(req.body?.message || '').trim();
  if (name.length < 2 || name.length > 100 || !/^\S+@\S+\.\S+$/.test(email) || phone.length < 5 || phone.length > 40 || area.length < 2 || area.length > 160 || message.length < 5 || message.length > 2000) {
    return res.status(400).json({ error: 'Complete each field with valid contact details.' });
  }
  const result = db.prepare('INSERT INTO enquiries (name, email, phone, area, message) VALUES (?, ?, ?, ?, ?)').run(name, email, phone, area, message);
  res.status(201).json({ enquiry: { id: Number(result.lastInsertRowid), message: 'Your enquiry has been received.' } });
});

app.use((error, _req, res, _next) => {
  if (error instanceof multer.MulterError) {
    const message = error.code === 'LIMIT_FILE_SIZE' ? 'Each image must be 8 MB or smaller.' : error.code === 'LIMIT_FILE_COUNT' ? 'Upload no more than 5 images.' : 'The image upload could not be processed.';
    return res.status(400).json({ error: message });
  }
  if (error.message === 'Only JPEG, PNG, and WebP images are allowed.') return res.status(400).json({ error: error.message });
  console.error(error);
  res.status(500).json({ error: 'The server encountered an error.' });
});

const port = Number(process.env.API_PORT || 4000);
app.listen(port, '127.0.0.1', () => console.log(`PropertyPlug101 API listening at http://127.0.0.1:${port}`));




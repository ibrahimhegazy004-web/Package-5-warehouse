const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;
const APP_NAME = process.env.APP_NAME || 'شركة تطوير الحزمة الخامسة - نظام إدارة المستودع';
const TOKEN_SECRET = process.env.TOKEN_SECRET || 'pkg5-local-secret-change-me';
const DEFAULT_ADMIN_USERNAME = process.env.DEFAULT_ADMIN_USERNAME || 'admin';
const DEFAULT_ADMIN_PASSWORD = process.env.DEFAULT_ADMIN_PASSWORD || 'Admin@12345';
const dbPath = path.join(__dirname, 'data', 'warehouse.db');
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new Database(dbPath);

app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, originalHash] = String(stored || '').split(':');
  if (!salt || !originalHash) return false;
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(originalHash, 'hex'));
}

function createToken(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(encoded).digest('base64url');
  return `${encoded}.${sig}`;
}

function verifyToken(token) {
  if (!token || !token.includes('.')) return null;
  const [encoded, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(encoded).digest('base64url');
  if (sig !== expected) return null;
  try {
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function authRequired(req, res, next) {
  if (req.path === '/api/login' || req.path === '/api/health') return next();
  const payload = verifyToken(req.cookies.pkg5_auth);
  if (!payload) return res.status(401).json({ error: 'غير مصرح. يرجى تسجيل الدخول.' });
  const user = db.prepare('SELECT id, username, full_name, role, is_active FROM users WHERE id = ?').get(payload.uid);
  if (!user || !user.is_active) return res.status(401).json({ error: 'المستخدم غير صالح.' });
  req.user = user;
  next();
}

function initDb() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      full_name TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'admin',
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS suppliers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      phone TEXT DEFAULT '',
      email TEXT DEFAULT '',
      address TEXT DEFAULT '',
      notes TEXT DEFAULT '',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      unit TEXT NOT NULL,
      category TEXT DEFAULT '',
      min_qty REAL DEFAULT 0,
      qty REAL DEFAULT 0,
      location TEXT DEFAULT '',
      supplier TEXT DEFAULT '',
      notes TEXT DEFAULT '',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      item_id INTEGER NOT NULL,
      trans_type TEXT NOT NULL CHECK(trans_type IN ('IN','OUT')),
      qty REAL NOT NULL,
      reference_no TEXT DEFAULT '',
      requested_by TEXT DEFAULT '',
      date TEXT NOT NULL,
      notes TEXT DEFAULT '',
      created_by TEXT DEFAULT '',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(item_id) REFERENCES items(id)
    );
  `);

  const adminCount = db.prepare('SELECT COUNT(*) AS count FROM users').get().count;
  if (adminCount === 0) {
    db.prepare(`INSERT INTO users (username, password_hash, full_name, role) VALUES (?, ?, ?, 'admin')`)
      .run(DEFAULT_ADMIN_USERNAME, hashPassword(DEFAULT_ADMIN_PASSWORD), 'مدير النظام');
  }

  const supplierCount = db.prepare('SELECT COUNT(*) AS count FROM suppliers').get().count;
  if (supplierCount === 0) {
    db.prepare(`INSERT INTO suppliers (name, phone, email, address, notes) VALUES (?, ?, ?, ?, ?)`)
      .run('مؤسسة التوريدات الحديثة', '0500000001', 'supplier1@example.com', 'الرياض', 'مورد مبدئي');
    db.prepare(`INSERT INTO suppliers (name, phone, email, address, notes) VALUES (?, ?, ?, ?, ?)`)
      .run('شركة المعدات الفنية', '0500000002', 'supplier2@example.com', 'الرياض', 'مورد مبدئي');
  }

  const itemCount = db.prepare('SELECT COUNT(*) AS count FROM items').get().count;
  if (itemCount === 0) {
    const seed = db.prepare(`INSERT INTO items (code, name, unit, category, min_qty, qty, location, supplier, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    seed.run('ITM-001', 'مواسير PVC 4 بوصة', 'قطعة', 'شبكات', 20, 150, 'A-01', 'مؤسسة التوريدات الحديثة', '');
    seed.run('ITM-002', 'أكواع 90 درجة', 'قطعة', 'شبكات', 30, 90, 'A-02', 'مؤسسة التوريدات الحديثة', '');
    seed.run('ITM-003', 'كيبل كهرباء 4 مم', 'متر', 'كهرباء', 100, 600, 'B-01', 'شركة المعدات الفنية', '');
  }
}
initDb();

app.use(authRequired);

function itemWithStatus(row) {
  if (!row) return row;
  return { ...row, status: Number(row.qty) <= Number(row.min_qty) ? 'low' : 'ok' };
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, app: APP_NAME });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username || '');
  if (!user || !user.is_active || !verifyPassword(password || '', user.password_hash)) {
    return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة.' });
  }
  const token = createToken({ uid: user.id, role: user.role, exp: Date.now() + (1000 * 60 * 60 * 10) });
  res.cookie('pkg5_auth', token, { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 1000 * 60 * 60 * 10 });
  res.json({ ok: true, user: { id: user.id, username: user.username, full_name: user.full_name, role: user.role } });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('pkg5_auth');
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  res.json({ user: req.user, appName: APP_NAME });
});

app.get('/api/dashboard', (req, res) => {
  const totalItems = db.prepare('SELECT COUNT(*) AS value FROM items').get().value;
  const totalQty = db.prepare('SELECT COALESCE(SUM(qty),0) AS value FROM items').get().value;
  const lowStock = db.prepare('SELECT COUNT(*) AS value FROM items WHERE qty <= min_qty').get().value;
  const transToday = db.prepare("SELECT COUNT(*) AS value FROM transactions WHERE date = date('now')").get().value;
  res.json({ totalItems, totalQty, lowStock, transToday });
});

app.get('/api/items', (req, res) => {
  const q = (req.query.q || '').trim();
  const rows = q
    ? db.prepare(`SELECT * FROM items WHERE code LIKE ? OR name LIKE ? OR category LIKE ? OR location LIKE ? OR supplier LIKE ? ORDER BY id DESC`).all(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`)
    : db.prepare('SELECT * FROM items ORDER BY id DESC').all();
  res.json(rows.map(itemWithStatus));
});

app.post('/api/items', (req, res) => {
  try {
    const { code, name, unit, category = '', min_qty = 0, qty = 0, location = '', supplier = '', notes = '' } = req.body;
    if (!code || !name || !unit) return res.status(400).json({ error: 'البيانات الأساسية مطلوبة.' });
    const result = db.prepare(`INSERT INTO items (code, name, unit, category, min_qty, qty, location, supplier, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(code, name, unit, category, Number(min_qty), Number(qty), location, supplier, notes);
    const row = db.prepare('SELECT * FROM items WHERE id = ?').get(result.lastInsertRowid);
    res.status(201).json(itemWithStatus(row));
  } catch (err) {
    res.status(500).json({ error: String(err.message).includes('UNIQUE') ? 'كود الصنف موجود مسبقًا.' : 'تعذر حفظ الصنف.' });
  }
});

app.put('/api/items/:id', (req, res) => {
  try {
    const id = Number(req.params.id);
    const existing = db.prepare('SELECT * FROM items WHERE id = ?').get(id);
    if (!existing) return res.status(404).json({ error: 'الصنف غير موجود.' });
    const data = { ...existing, ...req.body, min_qty: Number(req.body.min_qty ?? existing.min_qty), qty: Number(req.body.qty ?? existing.qty) };
    db.prepare(`UPDATE items SET code=?, name=?, unit=?, category=?, min_qty=?, qty=?, location=?, supplier=?, notes=? WHERE id=?`)
      .run(data.code, data.name, data.unit, data.category, data.min_qty, data.qty, data.location, data.supplier, data.notes, id);
    const row = db.prepare('SELECT * FROM items WHERE id = ?').get(id);
    res.json(itemWithStatus(row));
  } catch (err) {
    res.status(500).json({ error: String(err.message).includes('UNIQUE') ? 'كود الصنف موجود مسبقًا.' : 'تعذر تحديث الصنف.' });
  }
});

app.delete('/api/items/:id', (req, res) => {
  const id = Number(req.params.id);
  const existing = db.prepare('SELECT * FROM items WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'الصنف غير موجود.' });
  db.prepare('DELETE FROM transactions WHERE item_id = ?').run(id);
  db.prepare('DELETE FROM items WHERE id = ?').run(id);
  res.json({ ok: true });
});

app.get('/api/suppliers', (req, res) => {
  res.json(db.prepare('SELECT * FROM suppliers ORDER BY id DESC').all());
});

app.post('/api/suppliers', (req, res) => {
  try {
    const { name, phone = '', email = '', address = '', notes = '' } = req.body;
    if (!name) return res.status(400).json({ error: 'اسم المورد مطلوب.' });
    const result = db.prepare(`INSERT INTO suppliers (name, phone, email, address, notes) VALUES (?, ?, ?, ?, ?)`)
      .run(name, phone, email, address, notes);
    res.status(201).json(db.prepare('SELECT * FROM suppliers WHERE id = ?').get(result.lastInsertRowid));
  } catch (err) {
    res.status(500).json({ error: String(err.message).includes('UNIQUE') ? 'اسم المورد موجود مسبقًا.' : 'تعذر حفظ المورد.' });
  }
});

app.put('/api/suppliers/:id', (req, res) => {
  try {
    const id = Number(req.params.id);
    const existing = db.prepare('SELECT * FROM suppliers WHERE id = ?').get(id);
    if (!existing) return res.status(404).json({ error: 'المورد غير موجود.' });
    const data = { ...existing, ...req.body };
    db.prepare(`UPDATE suppliers SET name=?, phone=?, email=?, address=?, notes=? WHERE id=?`)
      .run(data.name, data.phone, data.email, data.address, data.notes, id);
    res.json(db.prepare('SELECT * FROM suppliers WHERE id = ?').get(id));
  } catch (err) {
    res.status(500).json({ error: String(err.message).includes('UNIQUE') ? 'اسم المورد موجود مسبقًا.' : 'تعذر تحديث المورد.' });
  }
});

app.delete('/api/suppliers/:id', (req, res) => {
  const id = Number(req.params.id);
  const existing = db.prepare('SELECT * FROM suppliers WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'المورد غير موجود.' });
  db.prepare('DELETE FROM suppliers WHERE id = ?').run(id);
  res.json({ ok: true });
});

app.get('/api/transactions', (req, res) => {
  const rows = db.prepare(`SELECT t.*, i.code AS item_code, i.name AS item_name, i.unit AS item_unit FROM transactions t INNER JOIN items i ON i.id = t.item_id ORDER BY t.id DESC LIMIT 300`).all();
  res.json(rows);
});

app.post('/api/transactions', (req, res) => {
  const { item_id, trans_type, qty, reference_no = '', requested_by = '', date, notes = '' } = req.body;
  if (!item_id || !trans_type || !qty || !date) return res.status(400).json({ error: 'البيانات الأساسية للحركة مطلوبة.' });
  const item = db.prepare('SELECT * FROM items WHERE id = ?').get(Number(item_id));
  if (!item) return res.status(404).json({ error: 'الصنف غير موجود.' });
  const movementQty = Number(qty);
  if (movementQty <= 0) return res.status(400).json({ error: 'الكمية يجب أن تكون أكبر من صفر.' });
  if (trans_type === 'OUT' && Number(item.qty) < movementQty) return res.status(400).json({ error: 'الرصيد غير كافٍ للصرف.' });
  const newQty = trans_type === 'IN' ? Number(item.qty) + movementQty : Number(item.qty) - movementQty;
  const tx = db.transaction(() => {
    db.prepare('UPDATE items SET qty = ? WHERE id = ?').run(newQty, item.id);
    db.prepare(`INSERT INTO transactions (item_id, trans_type, qty, reference_no, requested_by, date, notes, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(item.id, trans_type, movementQty, reference_no, requested_by, date, notes, req.user.username);
  });
  tx();
  res.status(201).json({ ok: true, newQty });
});

app.get('/api/export', (req, res) => {
  const payload = {
    users: db.prepare('SELECT id, username, full_name, role, is_active, created_at FROM users ORDER BY id DESC').all(),
    suppliers: db.prepare('SELECT * FROM suppliers ORDER BY id DESC').all(),
    items: db.prepare('SELECT * FROM items ORDER BY id DESC').all(),
    transactions: db.prepare('SELECT * FROM transactions ORDER BY id DESC').all(),
    exported_at: new Date().toISOString()
  };
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="pkg5-warehouse-backup.json"');
  res.send(JSON.stringify(payload, null, 2));
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`${APP_NAME} running on http://localhost:${PORT}`);
});

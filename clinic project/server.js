const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const path = require('path');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const PORT = 3000;

// Your specific Client ID
const CLIENT_ID = '680338956993-1frpc44346hm721g7mhlgd04dp38q5lv.apps.googleusercontent.com';
const googleClient = new OAuth2Client(CLIENT_ID);

// ─── DATABASE SETUP ───────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'canteen.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    role TEXT DEFAULT 'student',
    student_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS menu_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    stock INTEGER NOT NULL,
    emoji TEXT DEFAULT '🍱',
    available INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_code TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    user_email TEXT NOT NULL,
    user_name TEXT NOT NULL,
    total REAL NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    served_at DATETIME,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    menu_item_id INTEGER NOT NULL,
    menu_item_name TEXT NOT NULL,
    menu_item_emoji TEXT DEFAULT '🍱',
    quantity INTEGER NOT NULL,
    unit_price REAL NOT NULL,
    FOREIGN KEY(order_id) REFERENCES orders(id)
  );
`);

// Seed admin user using your specific email
const adminExists = db.prepare('SELECT id FROM users WHERE email = ?').get('jderramas251505@navotaspolytechniccollege.edu.ph');
if (!adminExists) {
  db.prepare('INSERT INTO users (email, name, role, student_id) VALUES (?, ?, ?, ?)').run(
    'jderramas251505@navotaspolytechniccollege.edu.ph', 'Canteen Admin', 'admin', 'ADM-001'
  );
}

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'npc-canteen-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));
app.use(express.static(path.join(__dirname, 'public')));

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Not authenticated' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin')
    return res.status(403).json({ error: 'Admin only' });
  next();
}

// ─── AUTH ROUTES ─────────────────────────────────────────────────────────────
app.post('/api/auth/google-login', async (req, res) => {
  const { credential, selectedRole, manualPassword } = req.body;
  if (!credential) return res.status(400).json({ error: 'Google Token required' });

  try {
    // 1. Verify the Google Token
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: CLIENT_ID,
    });
    
    const payload = ticket.getPayload();
    const email = payload.email.toLowerCase();
    const name = payload.name;

    // 2. Validate Domain
    const validDomain = email.endsWith('@navotaspolytechniccollege.edu.ph');
    if (!validDomain) {
      return res.status(403).json({
        error: 'Access denied. Only @navotaspolytechniccollege.edu.ph accounts are allowed.'
      });
    }

    // 3. Admin Check
    if (selectedRole === 'admin') {
      if (email !== 'jderramas251505@navotaspolytechniccollege.edu.ph') {
        return res.status(403).json({ error: 'This email is not registered as an admin.' });
      }
      if (manualPassword !== 'admin123') {
        return res.status(403).json({ error: 'Incorrect admin password.' });
      }
    }

    // 4. Upsert user in SQLite
    let user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) {
      const studentId = 'STU-' + Date.now().toString().slice(-6);
      db.prepare('INSERT INTO users (email, name, role, student_id) VALUES (?, ?, ?, ?)').run(
        email, name, 'student', studentId
      );
      user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    }

    // 5. Override role for session if Admin chooses to login as Student
    let activeRole = user.role;
    if (user.role === 'admin' && selectedRole === 'student') {
      activeRole = 'student';
    }

    // 6. Save session
    req.session.user = { id: user.id, email: user.email, name: user.name, role: activeRole, studentId: user.student_id };
    res.json({ success: true, user: req.session.user });

  } catch (error) {
    console.error(error);
    res.status(401).json({ error: 'Invalid Google authentication token.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({ user: null });
  res.json({ user: req.session.user });
});

// ─── MENU ROUTES ─────────────────────────────────────────────────────────────
app.get('/api/menu', requireAuth, (req, res) => {
  const items = db.prepare('SELECT * FROM menu_items WHERE available = 1 ORDER BY id DESC').all();
  res.json(items);
});

app.post('/api/menu', requireAdmin, (req, res) => {
  const { name, price, stock, emoji } = req.body;
  if (!name || !price || !stock) return res.status(400).json({ error: 'Missing fields' });
  const result = db.prepare('INSERT INTO menu_items (name, price, stock, emoji) VALUES (?, ?, ?, ?)').run(
    name, parseFloat(price), parseInt(stock), emoji || '🍱'
  );
  const item = db.prepare('SELECT * FROM menu_items WHERE id = ?').get(result.lastInsertRowid);
  res.json(item);
});

app.put('/api/menu/:id', requireAdmin, (req, res) => {
  const { name, price, stock, emoji } = req.body;
  db.prepare('UPDATE menu_items SET name=?, price=?, stock=?, emoji=? WHERE id=?').run(
    name, parseFloat(price), parseInt(stock), emoji, req.params.id
  );
  res.json({ success: true });
});

app.delete('/api/menu/:id', requireAdmin, (req, res) => {
  db.prepare('UPDATE menu_items SET available = 0 WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ─── ORDER ROUTES ─────────────────────────────────────────────────────────────
app.post('/api/orders', requireAuth, (req, res) => {
  const { items } = req.body; 
  const user = req.session.user;

  if (!items || items.length === 0) return res.status(400).json({ error: 'No items' });

  let total = 0;
  const resolvedItems = [];
  for (const item of items) {
    const menuItem = db.prepare('SELECT * FROM menu_items WHERE id = ? AND available = 1').get(item.menuItemId);
    if (!menuItem) return res.status(400).json({ error: `Item not found: ${item.menuItemId}` });
    if (menuItem.stock < item.quantity) return res.status(400).json({ error: `Not enough stock for ${menuItem.name}` });
    total += menuItem.price * item.quantity;
    resolvedItems.push({ menuItem, quantity: item.quantity });
  }

  const orderCode = 'NPC-' + Date.now().toString(36).toUpperCase() + '-' + Math.floor(Math.random() * 1000);

  const orderResult = db.prepare(
    'INSERT INTO orders (order_code, user_id, user_email, user_name, total) VALUES (?, ?, ?, ?, ?)'
  ).run(orderCode, user.id, user.email, user.name, total);

  const orderId = orderResult.lastInsertRowid;

  for (const { menuItem, quantity } of resolvedItems) {
    db.prepare(
      'INSERT INTO order_items (order_id, menu_item_id, menu_item_name, menu_item_emoji, quantity, unit_price) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(orderId, menuItem.id, menuItem.name, menuItem.emoji, quantity, menuItem.price);
    db.prepare('UPDATE menu_items SET stock = stock - ? WHERE id = ?').run(quantity, menuItem.id);
  }

  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
  const orderItems = db.prepare('SELECT * FROM order_items WHERE order_id = ?').all(orderId);

  res.json({ order, items: orderItems });
});

app.get('/api/orders', requireAuth, (req, res) => {
  const user = req.session.user;
  let orders;
  if (user.role === 'admin') {
    orders = db.prepare('SELECT * FROM orders ORDER BY created_at DESC').all();
  } else {
    orders = db.prepare('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC').all(user.id);
  }
  const result = orders.map(o => ({
    ...o,
    items: db.prepare('SELECT * FROM order_items WHERE order_id = ?').all(o.id)
  }));
  res.json(result);
});

app.get('/api/orders/pending', requireAdmin, (req, res) => {
  const orders = db.prepare("SELECT * FROM orders WHERE status = 'pending' ORDER BY created_at ASC").all();
  const result = orders.map(o => ({
    ...o,
    items: db.prepare('SELECT * FROM order_items WHERE order_id = ?').all(o.id)
  }));
  res.json(result);
});

app.put('/api/orders/:id/serve', requireAdmin, (req, res) => {
  db.prepare("UPDATE orders SET status = 'served', served_at = CURRENT_TIMESTAMP WHERE id = ?").run(req.params.id);
  res.json({ success: true });
});

app.get('/api/stats', requireAdmin, (req, res) => {
  const pending = db.prepare("SELECT COUNT(*) as c FROM orders WHERE status='pending'").get().c;
  const served = db.prepare("SELECT COUNT(*) as c FROM orders WHERE status='served'").get().c;
  const revenue = db.prepare("SELECT COALESCE(SUM(total),0) as s FROM orders WHERE status='served'").get().s;
  const users = db.prepare("SELECT COUNT(*) as c FROM users WHERE role='student'").get().c;
  res.json({ pending, served, revenue, users });
});

// ─── PAGES ────────────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/student', (req, res) => res.sendFile(path.join(__dirname, 'public', 'student.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

app.listen(PORT, () => {
  console.log(`\n✅  NPC Smart Canteen running at http://localhost:${PORT}`);
});
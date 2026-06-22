/**
 * MEDHAR — Klinik Karar Destek Sistemi
 * Backend Server — Express + JSON-DB + JWT
 * (Saf JavaScript — native derleme gerektirmez)
 */

const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const cors    = require('cors');
const path    = require('path');
const fs      = require('fs');

// ── Sabitler ──────────────────────────────────────────────
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'MEDHAR_SECRET_KEY_2026_GENOMIK';
const JWT_EXPIRY = '24h';
const DB_PATH    = path.join(__dirname, 'medhar_db.json');

// ══════════════════════════════════════════════════════════
// BASIT JSON VERİTABANI
// ══════════════════════════════════════════════════════════
function loadDB() {
  if (!fs.existsSync(DB_PATH)) return null;
  try { return JSON.parse(fs.readFileSync(DB_PATH, 'utf8')); } catch { return null; }
}

function saveDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf8');
}

function getDB() {
  let db = loadDB();
  if (!db) {
    db = { users: [], classifications: [], audit_logs: [], _nextId: { users:1, cls:1, log:1 } };
    saveDB(db);
  }
  return db;
}

function nextId(db, table) {
  const id = db._nextId[table] || 1;
  db._nextId[table] = id + 1;
  return id;
}

// ── Seed: Varsayılan kullanıcılar ─────────────────────────
function seedDatabase() {
  const db = getDB();
  if (db.users.length > 0) return; // Zaten seed yapılmış

  const seedUsers = [
    { email:'klinisyen@medhar.tr', password:'medhar2026', role:'klinisyen', name:'Dr. Ayşe Kaya' },
    { email:'uzman@medhar.tr',     password:'medhar2026', role:'uzman',     name:'Dr. Mehmet Demir' },
    { email:'analist@medhar.tr',   password:'medhar2026', role:'analist',   name:'Zeynep Yıldız' },
    { email:'admin@medhar.tr',     password:'medhar2026', role:'admin',     name:'Sistem Admin' },
    { email:'hoca@medhar.tr',      password:'hoca2026',   role:'hoca',      name:'Öğr. Gör. Değerlendirici' },
  ];

  for (const u of seedUsers) {
    db.users.push({
      id:            nextId(db,'users'),
      email:         u.email,
      password_hash: bcrypt.hashSync(u.password, 10),
      role:          u.role,
      name:          u.name,
      is_active:     1,
      last_login:    null,
      created_at:    new Date().toISOString(),
    });
  }

  // Seed analizler
  const klinId = db.users.find(u => u.role==='klinisyen')?.id || 1;
  const seedCls = [
    { variant_id:'VAR_004572', chromosome:'Chr17', gene:'TP53',  panel:'Herediter Kanser', label:'Patojenik', confidence:0.94, threshold:0.5 },
    { variant_id:'VAR_001979', chromosome:'Chr7',  gene:'CFTR',  panel:'CFTR Paneli',      label:'Patojenik', confidence:0.88, threshold:0.5 },
    { variant_id:'VAR_002962', chromosome:'Chr12', gene:'BMPR2', panel:'PAH Paneli',       label:'Benign',    confidence:0.12, threshold:0.5 },
    { variant_id:'VAR_006245', chromosome:'Chr1',  gene:'GNAS',  panel:'Genel (MASTER)',   label:'VUS',       confidence:0.48, threshold:0.5 },
    { variant_id:'VAR_001918', chromosome:'Chr7',  gene:'CFTR',  panel:'CFTR Paneli',      label:'Patojenik', confidence:0.91, threshold:0.5 },
  ];
  for (const c of seedCls) {
    db.classifications.push({ id:nextId(db,'cls'), ...c, user_id:klinId, created_at:new Date().toISOString() });
  }

  saveDB(db);
  console.log('✅ Veritabanı oluşturuldu ve örnek veriler eklendi:', DB_PATH);
}

seedDatabase();

// ── Express ───────────────────────────────────────────────
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname)); // HTML dosyasını sun

// ── JWT Middleware ─────────────────────────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Yetkilendirme gerekli' });
  }
  try {
    const token   = auth.slice(7);
    const payload = jwt.verify(token, JWT_SECRET);
    req.user      = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Geçersiz veya süresi dolmuş token' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Bu işlem için yetkiniz yok' });
    }
    next();
  };
}

function auditLog(userId, action, endpoint, req) {
  const db  = getDB();
  const ip  = req.ip || req.connection?.remoteAddress || 'unknown';
  db.audit_logs.push({ id:nextId(db,'log'), user_id:userId, action, endpoint, ip_addr:ip, timestamp:new Date().toISOString() });
  saveDB(db);
}

// ═══════════════════════════════════════════════════════════
// API ENDPOINTS
// ═══════════════════════════════════════════════════════════

// ── Sistem sağlığı ────────────────────────────────────────
app.get('/api/health', (req, res) => {
  const db = getDB();
  res.json({
    status:          'ok',
    uptime:          Math.round(process.uptime()),
    db:              'json-file',
    users:           db.users.length,
    classifications: db.classifications.length,
    timestamp:       new Date().toISOString(),
  });
});

// ── LOGIN ─────────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'E-posta ve şifre gerekli' });

  const db   = getDB();
  const user = db.users.find(u => u.email === email && u.is_active === 1);
  if (!user)                                    return res.status(401).json({ error: 'Geçersiz e-posta veya şifre' });
  if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'Geçersiz e-posta veya şifre' });

  user.last_login = new Date().toISOString();
  saveDB(db);
  auditLog(user.id, 'LOGIN', '/api/auth/login', req);

  const token = jwt.sign(
    { id:user.id, email:user.email, role:user.role, name:user.name },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRY }
  );

  res.json({ token, user:{ id:user.id, email:user.email, role:user.role, name:user.name } });
});

// ── LOGOUT ────────────────────────────────────────────────
app.post('/api/auth/logout', requireAuth, (req, res) => {
  auditLog(req.user.id, 'LOGOUT', '/api/auth/logout', req);
  res.json({ message: 'Başarıyla çıkış yapıldı' });
});

// ── Mevcut kullanıcı bilgisi ──────────────────────────────
app.get('/api/auth/me', requireAuth, (req, res) => {
  const db   = getDB();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
  const { password_hash, ...safe } = user;
  res.json(safe);
});

// ── Kullanıcı listesi (Admin) ──────────────────────────────
app.get('/api/users', requireAuth, requireRole('admin'), (req, res) => {
  const db = getDB();
  res.json(db.users.map(({ password_hash, ...u }) => u));
});

// ── Kullanıcı ekle (Admin) ────────────────────────────────
app.post('/api/users', requireAuth, requireRole('admin'), (req, res) => {
  const { email, password, role, name } = req.body;
  const validRoles = ['klinisyen','uzman','analist','admin','hoca'];
  if (!email || !password || !role || !name) return res.status(400).json({ error: 'Tüm alanlar gerekli' });
  if (!validRoles.includes(role)) return res.status(400).json({ error: 'Geçersiz rol' });

  const db = getDB();
  if (db.users.find(u => u.email === email)) return res.status(409).json({ error: 'Bu e-posta zaten kayıtlı' });

  const newUser = {
    id:            nextId(db, 'users'),
    email, role, name,
    password_hash: bcrypt.hashSync(password, 10),
    is_active:     1,
    last_login:    null,
    created_at:    new Date().toISOString(),
  };
  db.users.push(newUser);
  saveDB(db);
  auditLog(req.user.id, 'CREATE_USER', '/api/users', req);

  const { password_hash, ...safe } = newUser;
  res.json(safe);
});

// ── Kullanıcı güncelle (Admin) ────────────────────────────
app.patch('/api/users/:id', requireAuth, requireRole('admin'), (req, res) => {
  const db   = getDB();
  const user = db.users.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });

  if (req.body.name      !== undefined) user.name      = req.body.name;
  if (req.body.role      !== undefined) user.role      = req.body.role;
  if (req.body.is_active !== undefined) user.is_active = req.body.is_active;
  saveDB(db);
  auditLog(req.user.id, 'UPDATE_USER', `/api/users/${req.params.id}`, req);
  res.json({ message: 'Güncellendi' });
});

// ── Sınıflandırma geçmişi ─────────────────────────────────
app.get('/api/classifications', requireAuth, (req, res) => {
  const db = getDB();
  let cls  = db.classifications;

  // Klinisyen ve uzman sadece kendi kayıtlarını görebilir
  if (!['admin','analist'].includes(req.user.role)) {
    cls = cls.filter(c => c.user_id === req.user.id);
  }

  // Kullanıcı adını ekle
  const result = cls
    .slice(-50).reverse()
    .map(c => {
      const u = db.users.find(u => u.id === c.user_id);
      return { ...c, user_name: u?.name || '—', user_role: u?.role || '—' };
    });

  res.json(result);
});

// ── Yeni analiz kaydet ────────────────────────────────────
app.post('/api/classifications', requireAuth, (req, res) => {
  const { variant_id, chromosome, gene, panel, label, confidence, threshold } = req.body;
  if (!variant_id || !label || confidence === undefined) return res.status(400).json({ error: 'Eksik alan' });

  const db     = getDB();
  const newCls = {
    id: nextId(db, 'cls'),
    variant_id, chromosome, gene, panel, label,
    confidence, threshold: threshold ?? 0.5,
    user_id:    req.user.id,
    created_at: new Date().toISOString(),
  };
  db.classifications.push(newCls);
  saveDB(db);
  auditLog(req.user.id, `CLASSIFY:${label}`, '/api/classifications', req);
  res.json({ id: newCls.id, message: 'Analiz kaydedildi' });
});

// ── Dashboard istatistikleri ──────────────────────────────
app.get('/api/dashboard/stats', requireAuth, (req, res) => {
  const db    = getDB();
  const cls   = db.classifications;
  const total = cls.length;
  res.json({
    total,
    patojenik: cls.filter(c => c.label === 'Patojenik').length,
    benign:    cls.filter(c => c.label === 'Benign').length,
    vus:       cls.filter(c => c.label === 'VUS').length,
  });
});

// ── Audit log (Admin) ─────────────────────────────────────
app.get('/api/audit-logs', requireAuth, requireRole('admin'), (req, res) => {
  const db   = getDB();
  const logs = db.audit_logs.slice(-100).reverse().map(l => {
    const u = db.users.find(u => u.id === l.user_id);
    return { ...l, user_name: u?.name || '—', user_email: u?.email || '—' };
  });
  res.json(logs);
});

// ── HTML dosyasını sun ────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'MEDHAR_Web_Arayuzu.html'));
});

// ── Sunucuyu başlat ───────────────────────────────────────
app.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════╗');
  console.log('║   MEDHAR Klinik Karar Destek Sistemi         ║');
  console.log('║   Sunucu çalışıyor!                          ║');
  console.log(`║   ➜  http://localhost:${PORT}                   ║`);
  console.log('║                                              ║');
  console.log('║   Varsayılan Hesaplar:                       ║');
  console.log('║   klinisyen@medhar.tr / medhar2026           ║');
  console.log('║   uzman@medhar.tr     / medhar2026           ║');
  console.log('║   analist@medhar.tr   / medhar2026           ║');
  console.log('║   admin@medhar.tr     / medhar2026           ║');
  console.log('║                                              ║');
  console.log(`║   Veritabanı: medhar_db.json                 ║`);
  console.log('╚══════════════════════════════════════════════╝');
  console.log('');
});

// server.js
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const archiver = require('archiver');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// === CONFIG ===
const ROOT_DIR = path.resolve(__dirname, 'uploads'); // uploaded files
const ADMIN_USER = 'admin';
const ADMIN_PASS = 'guddiersigma9911';

// ensure uploads folder exists
if (!fs.existsSync(ROOT_DIR)) fs.mkdirSync(ROOT_DIR, { recursive: true });

// === MIDDLEWARE ===
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'replace-with-a-real-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

// serve static files from root folder
app.use(express.static(__dirname));

// === ADMIN CHECK ===
function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  return res.status(403).json({ error: 'Unauthorized' });
}

// === UTILS ===
function safeJoinRoot(relPath = '/') {
  const norm = path.normalize(relPath).replace(/^(\.\.[/\\])+/, '');
  const full = path.join(ROOT_DIR, norm);
  const resolved = path.resolve(full);
  if (!resolved.startsWith(ROOT_DIR)) throw new Error('Invalid path');
  return resolved;
}

function listDirectory(dirFullPath) {
  if (!fs.existsSync(dirFullPath)) return [];
  const names = fs.readdirSync(dirFullPath, { withFileTypes: true });
  return names.map(d => {
    const full = path.join(dirFullPath, d.name);
    const stats = fs.statSync(full);
    const relPath = '/' + path.relative(ROOT_DIR, full).replace(/\\/g, '/');
    const item = {
      name: d.name,
      path: relPath === '/.' ? '/' : relPath,
      type: d.isDirectory() ? 'DIR' : 'FILE',
      size: d.isFile() ? stats.size : undefined,
      mtime: stats.mtime
    };
    if (d.isDirectory()) {
      try { item.items = listDirectory(full); } catch (_) { item.items = []; }
    }
    return item;
  });
}

// === ROUTES ===

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    req.session.isAdmin = true;
    return res.json({ ok: true });
  }
  return res.status(401).json({ ok: false, error: 'Invalid credentials' });
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// Serve admin.html
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// List directory
app.get('/api/list', (req, res) => {
  const q = req.query.dir || '/';
  let full;
  try { full = safeJoinRoot(q); } catch { return res.status(400).json({ error: 'Invalid path' }); }
  try {
    const items = listDirectory(full);
    return res.json({ items });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to list directory' });
  }
});

// View file
app.get('/api/view/*', (req, res) => {
  const rel = req.params[0] || '';
  let full;
  try { full = safeJoinRoot(rel); } catch { return res.status(400).send('Invalid path'); }
  if (!fs.existsSync(full) || fs.statSync(full).isDirectory()) return res.status(404).send('File not found');
  res.sendFile(full);
});

// Download folder as zip
app.get('/api/download', (req, res) => {
  const q = req.query.dir || '/';
  let dirFull;
  try { dirFull = safeJoinRoot(q); } catch { return res.status(400).send('Invalid path'); }
  if (!fs.existsSync(dirFull) || !fs.statSync(dirFull).isDirectory()) return res.status(404).send('Directory not found');

  const zipName = path.basename(dirFull) || 'archive';
  res.setHeader('Content-Disposition', `attachment; filename="${zipName}.zip"`);
  res.setHeader('Content-Type', 'application/zip');

  const archive = archiver('zip', { zlib: { level: 9 } });
  archive.on('error', err => { console.error(err); res.status(500).end(); });
  archive.pipe(res);
  archive.directory(dirFull, false);
  archive.finalize();
});

// Delete (admin only)
app.post('/api/delete', requireAdmin, (req, res) => {
  const rel = req.body?.path;
  if (!rel) return res.status(400).json({ error: 'Missing path' });
  let full;
  try { full = safeJoinRoot(rel); } catch { return res.status(400).json({ error: 'Invalid path' }); }
  try { fs.rmSync(full, { recursive: true, force: true }); return res.json({ ok: true }); }
  catch (err) { console.error(err); return res.status(500).json({ error: 'Delete failed' }); }
});

// Upload (admin only)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const category = req.body.category || '/';
    const filepath = req.body.filepath || '';
    const subdir = path.dirname(filepath || file.originalname);
    const target = path.join(ROOT_DIR, category, subdir);
    try {
      const resolved = path.resolve(target);
      if (!resolved.startsWith(ROOT_DIR)) return cb(new Error('Invalid path'));
      fs.mkdirSync(resolved, { recursive: true });
      cb(null, resolved);
    } catch (err) { cb(err); }
  },
  filename: (req, file, cb) => {
    const filepath = req.body.filepath || '';
    const name = filepath ? path.basename(filepath) : file.originalname;
    cb(null, name);
  }
});
const upload = multer({ storage });

app.post('/api/upload', requireAdmin, upload.single('file'), (req, res) => {
  res.json({ ok: true });
});

// Serve index.html for root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Start server
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));

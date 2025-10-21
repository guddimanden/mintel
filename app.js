// app.js
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const archiver = require('archiver');
const cors = require('cors');

const app = express();
const PORT = 3000;

// === CONFIG ===
const ROOT_DIR = path.join(__dirname, 'uploads');
const ADMIN_USER = 'admin';
const ADMIN_PASS = 'StrongPassword123';

// === MIDDLEWARE ===
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: 'supersecretkey', resave: false, saveUninitialized: false }));
app.use(express.static('public'));

// Ensure upload dir exists
if (!fs.existsSync(ROOT_DIR)) fs.mkdirSync(ROOT_DIR, { recursive: true });

// === AUTH ===
function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  res.status(403).json({ error: 'Unauthorized' });
}

// === LOGIN/LOGOUT ===
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    req.session.isAdmin = true;
    return res.sendStatus(200);
  }
  res.sendStatus(401);
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.sendStatus(200));
});

// === LIST DIRECTORY ===
function listDirectory(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true }).map(f => {
    const full = path.join(dir, f.name);
    const stat = fs.statSync(full);
    const item = {
      name: f.name,
      path: full.replace(ROOT_DIR, '').replace(/\\/g, '/'),
      type: f.isDirectory() ? 'DIR' : 'FILE',
      size: f.isFile() ? stat.size : '-',
      mtime: stat.mtime.toISOString(),
    };
    return item;
  });
}

app.get('/api/list', (req, res) => {
  const dir = path.join(ROOT_DIR, req.query.dir || '/');
  if (!dir.startsWith(ROOT_DIR)) return res.status(400).json({ error: 'Invalid path' });
  try {
    const data = listDirectory(dir);
    res.json({ items: data });
  } catch (err) {
    res.status(404).json({ error: 'Directory not found' });
  }
});

// === VIEW / DOWNLOAD FILE ===
app.get('/api/view/*', (req, res) => {
  const filePath = path.join(ROOT_DIR, req.params[0]);
  if (!filePath.startsWith(ROOT_DIR) || !fs.existsSync(filePath)) return res.status(404).end();
  res.download(filePath);
});

// === DOWNLOAD FOLDER AS ZIP ===
app.get('/api/download', (req, res) => {
  const dirPath = path.join(ROOT_DIR, req.query.dir || '/');
  if (!dirPath.startsWith(ROOT_DIR) || !fs.existsSync(dirPath)) return res.status(400).end();

  const zipName = path.basename(dirPath) + '.zip';
  res.setHeader('Content-Disposition', `attachment; filename="${zipName}"`);
  res.setHeader('Content-Type', 'application/zip');

  const archive = archiver('zip', { zlib: { level: 9 } });
  archive.pipe(res);
  archive.directory(dirPath, false);
  archive.finalize();
});

// === DELETE FILE/FOLDER ===
app.post('/api/delete', requireAdmin, (req, res) => {
  const relPath = req.body.path;
  const target = path.join(ROOT_DIR, relPath);
  if (!target.startsWith(ROOT_DIR)) return res.status(400).end();
  if (fs.existsSync(target)) fs.rmSync(target, { recursive: true, force: true });
  res.sendStatus(200);
});

// === UPLOAD ===
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const targetDir = path.join(ROOT_DIR, req.body.category || '/');
    if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });
    cb(null, targetDir);
  },
  filename: (req, file, cb) => cb(null, file.originalname),
});
const upload = multer({ storage });

app.post('/api/upload', requireAdmin, upload.single('file'), (req, res) => res.sendStatus(200));

// === SERVE FRONTEND ===
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/tos', (req, res) => res.sendFile(path.join(__dirname, 'public', 'tos.html')));

// === START SERVER ===
app.listen(PORT, () => console.log(`✅ Server running at http://localhost:${PORT}`));

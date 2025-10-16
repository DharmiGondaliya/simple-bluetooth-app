// server.js – 2FA with role-based auth (everyone can access)
require('dotenv').config();

const path = require('path');
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const fsPromises = require('fs').promises;  // Changed: use fsPromises instead of fs
const fsSync = require('fs');               // Changed: use fsSync for synchronous operations
const multer = require('multer');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-change-this';

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from root directory (for HTML files)
app.use(express.static(__dirname));
// Also serve from public folder (for firmware files)
app.use(express.static(path.resolve('./public')));

/* ---------------- 2FA store & mailer ---------------- */
const verifyStore = new Map();
const CODE_TTL = parseInt(process.env.VERIFY_CODE_TTL_SEC || '600', 10);
const RESEND_COOLDOWN = parseInt(process.env.VERIFY_COOLDOWN_SEC || '60', 10);

const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || '2525', 10),
  secure: String(process.env.SMTP_SECURE || 'false') === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

function genCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

/* ------------- health check ------------- */
app.get('/auth/debug-smtp', async (req, res) => {
  try { 
    await mailer.verify(); 
    res.json({ ok: true }); 
  }
  catch (e) { 
    res.status(500).json({ ok: false, error: e.message }); 
  }
});

/* ------------- send code ------------- */
app.post('/auth/send-code', async (req, res) => {
  try {
    const identifier = String(req.body?.identifier || '').trim().toLowerCase();
    const role = String(req.body?.role || 'user').trim().toLowerCase();
    
    if (!identifier || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(identifier)) {
      return res.status(400).json({ error: 'Valid email required' });
    }

    // Everyone can access as user or admin - no restrictions
    
    const now = Date.now();
    const prev = verifyStore.get(identifier);
    if (prev && now - prev.lastSentAt < RESEND_COOLDOWN * 1000) {
      const wait = Math.ceil((RESEND_COOLDOWN * 1000 - (now - prev.lastSentAt)) / 1000);
      return res.status(429).json({ error: `Please wait ${wait}s before requesting again` });
    }

    const code = genCode();
    verifyStore.set(identifier, { 
      code, 
      role,
      expiresAt: now + CODE_TTL * 1000, 
      lastSentAt: now, 
      attempts: 0 
    });

    await mailer.sendMail({
      from: process.env.SMTP_FROM || `admin@teamplus.cloud`,
      to: identifier,
      subject: 'Your Team Plus verification code',
      text: `Your verification code is ${code}. It expires in ${Math.floor(CODE_TTL/60)} minutes.`,
      html: `<div style="font-family:Arial,sans-serif">
               <p>Your verification code:</p>
               <p style="font-size:28px;font-weight:700;letter-spacing:4px">${code}</p>
               <p>Expires in ${Math.floor(CODE_TTL/60)} minutes.</p>
             </div>`
    });

    res.json({ ok: true, message: 'Code sent' });
  } catch (e) {
    console.error('send-code error', e);
    res.status(500).json({ error: 'Failed to send code' });
  }
});

/* ------------- verify code ------------- */
app.post('/auth/verify-code', (req, res) => {
  const identifier = String(req.body?.identifier || '').trim().toLowerCase();
  const code = String(req.body?.code || '').trim();

  const entry = verifyStore.get(identifier);
  if (!entry) return res.status(400).json({ error: 'No code requested for this email' });

  const now = Date.now();
  if (now > entry.expiresAt) {
    verifyStore.delete(identifier);
    return res.status(400).json({ error: 'Code expired. Request a new one.' });
  }
  
  entry.attempts = (entry.attempts || 0) + 1;
  if (entry.attempts > 6) {
    verifyStore.delete(identifier);
    return res.status(429).json({ error: 'Too many attempts. Request a new code.' });
  }
  
  if (entry.code !== code) {
    return res.status(400).json({ error: 'Invalid code' });
  }

  // Generate JWT token
  const token = jwt.sign(
    { 
      email: identifier, 
      role: entry.role || 'user',
      iat: Math.floor(Date.now() / 1000)
    },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  verifyStore.delete(identifier);
  
  res.json({ 
    ok: true, 
    message: 'Email verified',
    token,
    role: entry.role || 'user',
    email: identifier
  });
});

/* ------------- verify token endpoint ------------- */
app.post('/auth/verify-token', (req, res) => {
  const token = req.body?.token;
  
  if (!token) {
    return res.status(401).json({ valid: false, error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ 
      valid: true, 
      email: decoded.email, 
      role: decoded.role 
    });
  } catch (e) {
    res.status(401).json({ valid: false, error: 'Invalid or expired token' });
  }
});

/* ------------- Admin-only send code (with email whitelist) ------------- */
app.post('/auth/admin-send-code', async (req, res) => {
  try {
    const identifier = String(req.body?.identifier || '').trim().toLowerCase();
    const role = String(req.body?.role || 'admin').trim().toLowerCase();
    
    if (!identifier || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(identifier)) {
      return res.status(400).json({ error: 'Valid email required' });
    }

    // Check if email is in admin whitelist
    const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
    
    if (ADMIN_EMAILS.length > 0 && !ADMIN_EMAILS.includes(identifier)) {
      console.log(`Access denied for ${identifier} - not in admin whitelist`);
      return res.status(403).json({ 
        error: 'Access denied. This email is not authorized for admin access.' 
      });
    }
    
    const now = Date.now();
    const prev = verifyStore.get(identifier);
    if (prev && now - prev.lastSentAt < RESEND_COOLDOWN * 1000) {
      const wait = Math.ceil((RESEND_COOLDOWN * 1000 - (now - prev.lastSentAt)) / 1000);
      return res.status(429).json({ error: `Please wait ${wait}s before requesting again` });
    }

    const code = genCode();
    verifyStore.set(identifier, { 
      code, 
      role,
      expiresAt: now + CODE_TTL * 1000, 
      lastSentAt: now, 
      attempts: 0 
    });

    await mailer.sendMail({
      from: process.env.SMTP_FROM || `admin@teamplus.cloud`,
      to: identifier,
      subject: 'Team Plus Admin - Verification Code',
      text: `Your admin verification code is ${code}. It expires in ${Math.floor(CODE_TTL/60)} minutes.`,
      html: `<div style="font-family:Arial,sans-serif">
               <h2 style="color:#003366">Admin Login Verification</h2>
               <p>Your verification code:</p>
               <p style="font-size:32px;font-weight:700;letter-spacing:6px;color:#003366">${code}</p>
               <p>Expires in ${Math.floor(CODE_TTL/60)} minutes.</p>
               <p style="color:#666;font-size:12px">This code is for admin access only.</p>
             </div>`
    });

    console.log(`✓ Admin verification code sent to ${identifier}`);
    res.json({ ok: true, message: 'Code sent' });
  } catch (e) {
    console.error('admin-send-code error', e);
    res.status(500).json({ error: 'Failed to send code' });
  }
});
/* ============================================
   ADMIN API ENDPOINTS - Firmware Management
   ============================================ */

// Firmware directory path
const FIRMWARE_DIR = path.join(__dirname, 'public', 'firmware');

// Ensure firmware directory exists
if (!fsSync.existsSync(FIRMWARE_DIR)) {
  fsSync.mkdirSync(FIRMWARE_DIR, { recursive: true });
}

/* ========= FILE UPLOAD CONFIGURATION ========= */
const upload = multer({ 
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    if (file.originalname.endsWith('.bin')) {
      cb(null, true);
    } else {
      cb(new Error('Only .bin files are allowed'));
    }
  },
  limits: {
    fileSize: 50 * 1024 * 1024
  }
});

// GET /api/directories - List all firmware directories
app.get('/api/directories', async (req, res) => {
  try {
    console.log('GET /api/directories - Reading:', FIRMWARE_DIR);
    const entries = await fsPromises.readdir(FIRMWARE_DIR, { withFileTypes: true });
    const directories = entries
      .filter(entry => entry.isDirectory())
      .map(entry => entry.name)
      .sort();
    
    console.log('Found directories:', directories);
    res.json({ ok: true, directories });
  } catch (error) {
    console.error('Error reading directories:', error);
    res.status(500).json({ ok: false, error: 'Failed to read directories' });
  }
});

// POST /api/directories - Create new directory
app.post('/api/directories', async (req, res) => {
  try {
    const { name } = req.body;
    
    if (!name || !/^[a-zA-Z0-9-_\s]+$/.test(name)) {
      return res.status(400).json({ 
        ok: false, 
        error: 'Invalid directory name. Use only letters, numbers, spaces, hyphens, and underscores.' 
      });
    }

    const firmwarePath = path.join(FIRMWARE_DIR, name);
    
    if (fsSync.existsSync(firmwarePath)) {
      return res.status(400).json({ 
        ok: false, 
        error: 'Directory already exists' 
      });
    }

    await fsPromises.mkdir(firmwarePath, { recursive: true });
    
    console.log(`✓ Created directory: ${name}`);
    res.json({ ok: true, message: 'Directory created successfully' });
  } catch (error) {
    console.error('Error creating directory:', error);
    res.status(500).json({ ok: false, error: 'Failed to create directory' });
  }
});


// DELETE /api/directories/:name - Delete directory
app.delete('/api/directories/:name', async (req, res) => {
  try {
    const dirName = decodeURIComponent(req.params.name);
    const firmwarePath = path.join(FIRMWARE_DIR, dirName);
    
    if (!fsSync.existsSync(firmwarePath)) {
      return res.status(404).json({ ok: false, error: 'Directory not found' });
    }

    await fsPromises.rm(firmwarePath, { recursive: true, force: true });
    
    console.log(`✓ Deleted directory: ${dirName}`);
    res.json({ ok: true, message: 'Directory deleted successfully' });
  } catch (error) {
    console.error('Error deleting directory:', error);
    res.status(500).json({ ok: false, error: 'Failed to delete directory' });
  }
});

// GET /api/files - List files in a directory
app.get('/api/files', async (req, res) => {
  try {
    const directory = req.query.directory;
    
    if (!directory) {
      return res.status(400).json({ ok: false, error: 'Directory parameter required' });
    }

    const dirPath = path.join(FIRMWARE_DIR, directory);
    
    if (!fsSync.existsSync(dirPath)) {
      return res.json({ ok: true, files: [] });
    }

    const entries = await fsPromises.readdir(dirPath, { withFileTypes: true });
    const files = await Promise.all(
      entries
        .filter(entry => entry.isFile())
        .map(async (entry) => {
          const filePath = path.join(dirPath, entry.name);
          const stats = await fsPromises.stat(filePath);
          return {
            name: entry.name,
            size: stats.size,
            modified: stats.mtime,
            url: `/firmware/${directory}/${entry.name}`
          };
        })
    );
    
    res.json({ ok: true, files: files.sort((a, b) => b.modified - a.modified) });
  } catch (error) {
    console.error('Error reading files:', error);
    res.status(500).json({ ok: false, error: 'Failed to read files' });
  }
});

// POST /api/upload - Upload firmware file
app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    console.log('Upload request received');
    console.log('Body:', req.body);
    console.log('File:', req.file ? req.file.originalname : 'no file');

    if (!req.file) {
      console.log('Error: No file in request');
      return res.status(400).json({ ok: false, error: 'No file uploaded' });
    }

    const directory = req.body.directory;
    
    if (!directory) {
      console.log('Error: No directory in request body');
      return res.status(400).json({ ok: false, error: 'Directory name is required' });
    }

    const firmwarePath = path.join(FIRMWARE_DIR, directory);
    console.log('Target path:', firmwarePath);
    
    // Create directory if it doesn't exist
    if (!fsSync.existsSync(firmwarePath)) {
      console.log('Creating directory:', firmwarePath);
      fsSync.mkdirSync(firmwarePath, { recursive: true });
    }

    // Write file from memory buffer to disk
    const filePath = path.join(firmwarePath, req.file.originalname);
    await fsPromises.writeFile(filePath, req.file.buffer);

    console.log(`✓ SUCCESS: Uploaded ${req.file.originalname} to ${directory} (${req.file.size} bytes)`);
    
    res.json({ 
      ok: true, 
      message: 'File uploaded successfully',
      filename: req.file.originalname,
      size: req.file.size
    });
  } catch (error) {
    console.error('❌ Upload error:', error);
    res.status(500).json({ ok: false, error: error.message || 'Failed to upload file' });
  }
});

// PUT /api/files/rename - Rename a file
app.put('/api/files/rename', async (req, res) => {
  const { directory, oldName, newName } = req.body;
  
  // Validate inputs
  if (!directory || !oldName || !newName) {
    return res.json({ ok: false, error: 'Missing required fields' });
  }
  
  if (!newName.endsWith('.bin')) {
    return res.json({ ok: false, error: 'New filename must end with .bin' });
  }
  
  const oldPath = path.join(FIRMWARE_DIR, directory, oldName);
  const newPath = path.join(FIRMWARE_DIR, directory, newName);
  
  // Check if old file exists
  if (!fsSync.existsSync(oldPath)) {
    return res.json({ ok: false, error: 'Original file not found' });
  }
  
  // Check if new filename already exists
  if (fsSync.existsSync(newPath)) {
    return res.json({ ok: false, error: 'A file with that name already exists' });
  }
  
  try {
    fsSync.renameSync(oldPath, newPath);
    console.log(`✓ Renamed file: ${oldName} → ${newName} in ${directory}`);
    res.json({ ok: true, message: 'File renamed successfully' });
  } catch (error) {
    console.error('Rename error:', error);
    res.json({ ok: false, error: 'Failed to rename file' });
  }
});

// PUT /api/directories/rename - Rename a directory
app.put('/api/directories/rename', async (req, res) => {
  const { oldName, newName } = req.body;
  
  if (!oldName || !newName) {
    return res.json({ ok: false, error: 'Missing required fields' });
  }
  
  const validName = /^[a-zA-Z0-9\s\-_]+$/.test(newName);
  if (!validName) {
    return res.json({ 
      ok: false, 
      error: 'Directory name can only contain letters, numbers, spaces, hyphens, and underscores' 
    });
  }
  
  const oldPath = path.join(FIRMWARE_DIR, oldName);
  const newPath = path.join(FIRMWARE_DIR, newName);
  
  if (!fsSync.existsSync(oldPath)) {
    return res.json({ ok: false, error: 'Original directory not found' });
  }
  
  if (fsSync.existsSync(newPath)) {
    return res.json({ ok: false, error: 'A directory with that name already exists' });
  }
  
  try {
    fsSync.renameSync(oldPath, newPath);
    console.log(`✓ Renamed directory: ${oldName} → ${newName}`);
    res.json({ ok: true, message: 'Directory renamed successfully' });
  } catch (error) {
    console.error('Directory rename error:', error);
    res.json({ ok: false, error: 'Failed to rename directory' });
  }
});
// DELETE /api/files - Delete a file
app.delete('/api/files', async (req, res) => {
  try {
    const { directory, filename } = req.body;
    
    if (!directory || !filename) {
      return res.status(400).json({ ok: false, error: 'Directory and filename required' });
    }

    const filePath = path.join(FIRMWARE_DIR, directory, filename);
    
    if (!fsSync.existsSync(filePath)) {
      return res.status(404).json({ ok: false, error: 'File not found' });
    }

    await fsPromises.unlink(filePath);
    
    console.log(`✓ Deleted file: ${filename} from ${directory}`);
    res.json({ ok: true, message: 'File deleted successfully' });
  } catch (error) {
    console.error('Error deleting file:', error);
    res.status(500).json({ ok: false, error: 'Failed to delete file' });
  }
});

/* ------------- start ------------- */
app.listen(PORT, () => {
  console.log(`▶ 2FA server running on http://localhost:3000`);
  console.log(`   CORS enabled.`);
});

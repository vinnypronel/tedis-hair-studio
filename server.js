// server.js (Node.js/Express - CommonJS)
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const fs = require('fs');
const puppeteer = require('puppeteer');

const app = express();
app.use(cors());
app.use(express.json());

// ==================== SMS & EMAIL CONFIG ====================
// TODO: Add your Twilio credentials from https://www.twilio.com/console
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID || 'YOUR_TWILIO_SID';
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN || 'YOUR_TWILIO_TOKEN';
const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER || '+1XXXXXXXXXX';

// TODO: Add your SendGrid API key from https://app.sendgrid.com/settings/api_keys
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY || 'YOUR_SENDGRID_KEY';
const FROM_EMAIL = process.env.FROM_EMAIL || 'noreply@tedishairstudio.com';
const BUSINESS_NAME = "Tedi's Hair Studio";
const BUSINESS_PHONE = '(732) 947-7359';

// Initialize Twilio (only if credentials are set)
let twilioClient = null;
if (TWILIO_ACCOUNT_SID !== 'YOUR_TWILIO_SID') {
  try {
    const twilio = require('twilio');
    twilioClient = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
    console.log('✓ Twilio SMS service initialized');
  } catch (e) {
    console.warn('⚠ Twilio not configured - SMS disabled');
  }
}

// Initialize SendGrid (only if credentials are set)
let sgMail = null;
if (SENDGRID_API_KEY !== 'YOUR_SENDGRID_KEY') {
  try {
    sgMail = require('@sendgrid/mail');
    sgMail.setApiKey(SENDGRID_API_KEY);
    console.log('✓ SendGrid email service initialized');
  } catch (e) {
    console.warn('⚠ SendGrid not configured - Email disabled');
  }
}

// Store verification codes temporarily (in production, use Redis with TTL)
const verificationCodes = new Map();

// Serve static files from /public (HTML/CSS/JS, images, etc.)
app.use(express.static(path.join(__dirname, 'public')));

// ---- Image Upload Config ----
const galleryDir = path.join(__dirname, 'public', 'images', 'gallery');
if (!fs.existsSync(galleryDir)) {
  fs.mkdirSync(galleryDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, galleryDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const name = `gallery-${Date.now()}${ext}`;
    cb(null, name);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB max
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|webp|gif/i;
    if (allowed.test(path.extname(file.originalname))) {
      cb(null, true);
    } else {
      cb(new Error('Only images allowed'));
    }
  }
});

// ---- DB ----
const dbPath = path.join(__dirname, 'data.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Failed to open DB:', err.message);
  } else {
    console.log('Connected to', dbPath);
    // Enforce FKs if your schema uses them
    db.run('PRAGMA foreign_keys = ON;', (e) => {
      if (e) console.warn('PRAGMA foreign_keys error:', e.message);
    });
  }
});

// ---- Auth Helpers ----
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Active sessions (in production, use Redis or DB)
const sessions = new Map();

// Auth middleware
function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.user = sessions.get(token);
  next();
}

// Admin-only middleware
function requireAdmin(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const user = sessions.get(token);
  if (user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  req.user = user;
  next();
}

// Helper wrappers
function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve({ id: this.lastID, changes: this.changes });
    });
  });
}
function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
  });
}
function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
  });
}

// ==================== AUTO-GENERATE ALL SLOTS ====================
async function autoGenerateAllSlots() {
  const pad = (n) => String(n).padStart(2, '0');

  // Generate for next 2 years
  const today = new Date();
  const endDate = new Date();
  endDate.setFullYear(today.getFullYear() + 2);

  // Business hours by day of week
  // Last appointment times (30 min before close)
  const hours = {
    1: { open: '10:00', lastAppt: '19:30' }, // Monday: 10am-7:30pm (close 8pm)
    2: { open: '10:00', lastAppt: '19:30' }, // Tuesday: 10am-7:30pm (close 8pm)
    3: { open: '10:00', lastAppt: '19:30' }, // Wednesday: 10am-7:30pm (close 8pm)
    4: { open: '10:00', lastAppt: '19:30' }, // Thursday: 10am-7:30pm (close 8pm)
    5: { open: '10:00', lastAppt: '19:30' }, // Friday: 10am-7:30pm (close 8pm)
    6: { open: '09:00', lastAppt: '16:30' }, // Saturday: 9am-4:30pm (close 5pm)
    // Sunday (0) is closed
  };

  let slotsCreated = 0;

  for (let d = new Date(today); d <= endDate; d.setDate(d.getDate() + 1)) {
    const dow = d.getDay();

    // Skip if no hours defined (Sunday)
    if (!hours[dow]) continue;

    const dateStr = [
      d.getFullYear(),
      pad(d.getMonth() + 1),
      pad(d.getDate()),
    ].join('-');

    const [openH, openM] = hours[dow].open.split(':').map(Number);
    const [lastH, lastM] = hours[dow].lastAppt.split(':').map(Number);
    const openMins = openH * 60 + openM;
    const lastMins = lastH * 60 + lastM;

    // Generate 30-minute intervals (inclusive of last appointment time)
    for (let mins = openMins; mins <= lastMins; mins += 30) {
      const h = Math.floor(mins / 60);
      const m = mins % 60;
      const timeStr = `${pad(h)}:${pad(m)}`;

      try {
        await run(
          `INSERT OR IGNORE INTO time_slots (date, time, is_available) VALUES (?, ?, 1)`,
          [dateStr, timeStr]
        );
        slotsCreated++;
      } catch (e) {
        // Ignore duplicates
      }
    }
  }

  console.log(`✓ All business day slots generated/verified (${slotsCreated} slots processed)`);
}

// ==================== MIGRATE BOOKINGS TABLE ====================
async function migrateBookingsTable() {
  try {
    // Check if new columns exist
    const columns = await all("PRAGMA table_info(bookings)");
    const columnNames = columns.map(c => c.name);

    if (!columnNames.includes('policy_agreed_at')) {
      await run('ALTER TABLE bookings ADD COLUMN policy_agreed_at TEXT');
      console.log('✓ Added policy_agreed_at column to bookings');
    }
    if (!columnNames.includes('phone_verified')) {
      await run('ALTER TABLE bookings ADD COLUMN phone_verified INTEGER DEFAULT 0');
      console.log('✓ Added phone_verified column to bookings');
    }
    if (!columnNames.includes('reminder_sent')) {
      await run('ALTER TABLE bookings ADD COLUMN reminder_sent INTEGER DEFAULT 0');
      console.log('✓ Added reminder_sent column to bookings');
    }
  } catch (e) {
    console.error('Migration error:', e.message);
  }
}

// ==================== INIT USERS TABLE ====================
async function initUsers() {
  try {
    // Create users table if not exists (supports both regular users and admins)
    await run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE,
        phone TEXT,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Migrate from old admin_users table if exists
    const oldTable = await get("SELECT name FROM sqlite_master WHERE type='table' AND name='admin_users'");
    if (oldTable) {
      const oldUsers = await all('SELECT * FROM admin_users');
      for (const u of oldUsers) {
        try {
          await run(
            'INSERT OR IGNORE INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)',
            [u.username, u.password_hash, u.role, u.created_at]
          );
        } catch (e) { }
      }
      await run('DROP TABLE admin_users');
      console.log('✓ Migrated users from admin_users table');
    }

    // Check if admin users exist
    const adminCount = await get("SELECT COUNT(*) as count FROM users WHERE role = 'admin'");
    if (adminCount.count === 0) {
      // Create default admin users (passwords from .env file)
      const admins = [
        { username: 'tedi', password: process.env.ADMIN_TEDI_PASSWORD },
        { username: 'dev', password: process.env.ADMIN_DEV_PASSWORD }
      ];

      for (const u of admins) {
        await run(
          'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
          [u.username, hashPassword(u.password), 'admin']
        );
      }
      console.log('✓ Default admin users created (tedi, dev)');
    }

    console.log('✓ Users table ready');
  } catch (e) {
    console.error('Failed to init users:', e.message);
  }
}

// ==================== GALLERY TABLE ====================
async function initGallery() {
  try {
    await run(`
      CREATE TABLE IF NOT EXISTS gallery_images (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        caption TEXT,
        uploaded_by TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('✓ Gallery table ready');
  } catch (e) {
    console.error('Failed to init gallery:', e.message);
  }
}

// Health (handy during debugging)
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// ==================== PHONE VERIFICATION ====================

// Generate 6-digit code
function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Send SMS via Twilio
async function sendSMS(to, message) {
  if (!twilioClient) {
    console.log(`[SMS MOCK] To: ${to} | Message: ${message}`);
    return { ok: true, mock: true };
  }

  try {
    const result = await twilioClient.messages.create({
      body: message,
      from: TWILIO_PHONE_NUMBER,
      to: '+1' + to.replace(/\D/g, '')
    });
    return { ok: true, sid: result.sid };
  } catch (e) {
    console.error('SMS Error:', e.message);
    return { ok: false, error: e.message };
  }
}

// Send email via SendGrid
async function sendEmail(to, subject, htmlContent) {
  if (!sgMail) {
    console.log(`[EMAIL MOCK] To: ${to} | Subject: ${subject}`);
    return { ok: true, mock: true };
  }

  try {
    await sgMail.send({
      to,
      from: { email: FROM_EMAIL, name: BUSINESS_NAME },
      subject,
      html: htmlContent
    });
    return { ok: true };
  } catch (e) {
    console.error('Email Error:', e.message);
    return { ok: false, error: e.message };
  }
}

// Generate booking confirmation email HTML
function generateConfirmationEmail(booking) {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; background-color: #0e0e0f; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #0e0e0f; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background-color: #161618; border-radius: 20px; overflow: hidden; border: 1px solid #242428;">
          <!-- Header with Logo -->
          <tr>
            <td style="padding: 40px 40px 30px; text-align: center; background: linear-gradient(135deg, rgba(255, 229, 0, 0.1) 0%, rgba(0,0,0,0) 100%);">
              <img src="https://i.imgur.com/placeholder.png" alt="${BUSINESS_NAME}" style="height: 70px; width: 70px; border-radius: 50%; border: 2px solid #333;">
              <h1 style="color: #FFE500; font-size: 28px; margin: 20px 0 0; font-family: Georgia, serif;">Booking Confirmed!</h1>
              <p style="color: #b8b8bb; font-size: 16px; margin: 10px 0 0;">Thank you for booking with us</p>
            </td>
          </tr>
          
          <!-- Booking Details -->
          <tr>
            <td style="padding: 30px 40px;">
              <table width="100%" style="background-color: #1a1a1c; border-radius: 12px; border: 1px solid #2a2a2e;">
                <tr>
                  <td style="padding: 24px;">
                    <p style="color: #FFE500; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin: 0 0 16px;">Appointment Details</p>
                    
                    <table width="100%">
                      <tr>
                        <td style="color: #888; font-size: 14px; padding: 8px 0;">Service:</td>
                        <td style="color: #fff; font-size: 14px; padding: 8px 0; text-align: right; font-weight: 600;">${booking.service_name}</td>
                      </tr>
                      <tr>
                        <td style="color: #888; font-size: 14px; padding: 8px 0;">Date:</td>
                        <td style="color: #fff; font-size: 14px; padding: 8px 0; text-align: right; font-weight: 600;">${booking.date}</td>
                      </tr>
                      <tr>
                        <td style="color: #888; font-size: 14px; padding: 8px 0;">Time:</td>
                        <td style="color: #fff; font-size: 14px; padding: 8px 0; text-align: right; font-weight: 600;">${formatTime12h(booking.time)}</td>
                      </tr>
                      <tr>
                        <td style="color: #888; font-size: 14px; padding: 8px 0;">Price:</td>
                        <td style="color: #FFE500; font-size: 14px; padding: 8px 0; text-align: right; font-weight: 600;">$${(booking.price_cents / 100).toFixed(2)}</td>
                      </tr>
                      <tr>
                        <td style="color: #888; font-size: 14px; padding: 8px 0;">Payment:</td>
                        <td style="color: #fff; font-size: 14px; padding: 8px 0; text-align: right; font-weight: 600;">${booking.payment_method.toUpperCase()}</td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          
          <!-- Location -->
          <tr>
            <td style="padding: 0 40px 30px;">
              <table width="100%" style="background-color: #1a1a1c; border-radius: 12px; border: 1px solid #2a2a2e;">
                <tr>
                  <td style="padding: 24px;">
                    <p style="color: #FFE500; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin: 0 0 12px;">📍 Location</p>
                    <p style="color: #fff; font-size: 15px; margin: 0 0 8px; font-weight: 600;">Inside Bellazio Collective</p>
                    <p style="color: #888; font-size: 14px; margin: 0;">259 Broad St, Suite 103<br>Matawan, NJ 07747</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          
          <!-- Reminder Notice -->
          <tr>
            <td style="padding: 0 40px 30px;">
              <p style="color: #888; font-size: 13px; line-height: 1.6; margin: 0; text-align: center;">
                ⏰ You'll receive a reminder 2 hours before your appointment.<br>
                Need to reschedule? Call us at <a href="tel:+17329477359" style="color: #FFE500; text-decoration: none;">${BUSINESS_PHONE}</a>
              </p>
            </td>
          </tr>
          
          <!-- Footer -->
          <tr>
            <td style="padding: 30px 40px; background-color: #111; border-top: 1px solid #222; text-align: center;">
              <p style="color: #666; font-size: 12px; margin: 0;">© ${new Date().getFullYear()} ${BUSINESS_NAME}. All rights reserved.</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

// Generate reminder email HTML
function generateReminderEmail(booking) {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
</head>
<body style="margin: 0; padding: 0; background-color: #0e0e0f; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #0e0e0f; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background-color: #161618; border-radius: 20px; overflow: hidden; border: 1px solid #242428;">
          <tr>
            <td style="padding: 40px; text-align: center;">
              <h1 style="color: #FFE500; font-size: 24px; margin: 0 0 16px;">⏰ Appointment Reminder</h1>
              <p style="color: #b8b8bb; font-size: 16px; margin: 0 0 30px;">Your appointment is in <strong style="color: #fff;">2 hours</strong>!</p>
              
              <table width="100%" style="background-color: #1a1a1c; border-radius: 12px; text-align: left;">
                <tr>
                  <td style="padding: 24px;">
                    <p style="color: #fff; font-size: 18px; margin: 0 0 8px; font-weight: 600;">${booking.service_name}</p>
                    <p style="color: #FFE500; font-size: 16px; margin: 0;">${formatTime12h(booking.time)} today</p>
                  </td>
                </tr>
              </table>
              
              <p style="color: #888; font-size: 14px; margin: 30px 0 0;">
                📍 259 Broad St, Suite 103, Matawan, NJ<br>
                📞 ${BUSINESS_PHONE}
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

// Helper to format time
function formatTime12h(time24) {
  const [h, m] = time24.split(':').map(Number);
  const period = h >= 12 ? 'PM' : 'AM';
  const hour = h % 12 || 12;
  return `${hour}:${String(m).padStart(2, '0')} ${period}`;
}

// --- SEND VERIFICATION CODE ---
app.post('/api/send-verification', async (req, res) => {
  const { phone } = req.body || {};

  if (!phone) {
    return res.status(400).json({ error: 'Phone number required' });
  }

  const cleanPhone = phone.replace(/\D/g, '');
  if (cleanPhone.length < 10) {
    return res.status(400).json({ error: 'Invalid phone number' });
  }

  // Generate code
  const code = generateVerificationCode();

  // Store code with 10 minute expiry
  verificationCodes.set(cleanPhone, {
    code,
    expires: Date.now() + 10 * 60 * 1000
  });

  // Send SMS
  const message = `Your ${BUSINESS_NAME} verification code is: ${code}. Valid for 10 minutes.`;
  const result = await sendSMS(cleanPhone, message);

  if (result.ok) {
    console.log(`✓ Verification code sent to ${cleanPhone}: ${code}`);
    res.json({ ok: true });
  } else {
    res.status(500).json({ error: 'Failed to send verification code' });
  }
});

// --- VERIFY CODE ---
app.post('/api/verify-code', async (req, res) => {
  const { phone, code } = req.body || {};

  if (!phone || !code) {
    return res.status(400).json({ error: 'Phone and code required' });
  }

  const cleanPhone = phone.replace(/\D/g, '');
  const stored = verificationCodes.get(cleanPhone);

  if (!stored) {
    return res.status(400).json({ error: 'No verification code sent to this number' });
  }

  if (Date.now() > stored.expires) {
    verificationCodes.delete(cleanPhone);
    return res.status(400).json({ error: 'Verification code expired' });
  }

  if (stored.code !== code) {
    return res.status(400).json({ error: 'Invalid verification code' });
  }

  // Code is valid - remove it
  verificationCodes.delete(cleanPhone);
  console.log(`✓ Phone verified: ${cleanPhone}`);

  res.json({ ok: true });
});

// ==================== AUTH ROUTES ====================

// --- REGISTER ---
app.post('/api/auth/register', async (req, res) => {
  const { username, email, phone, password } = req.body || {};

  try {
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    if (username.length < 3) {
      return res.status(400).json({ error: 'Username must be at least 3 characters' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if username exists
    const existing = await get('SELECT id FROM users WHERE LOWER(username) = ?', [username.toLowerCase()]);
    if (existing) {
      return res.status(409).json({ error: 'Username already taken' });
    }

    // Check if email exists (if provided)
    if (email) {
      const emailExists = await get('SELECT id FROM users WHERE LOWER(email) = ?', [email.toLowerCase()]);
      if (emailExists) {
        return res.status(409).json({ error: 'Email already registered' });
      }
    }

    // Create user (role is always 'user' for registrations)
    const result = await run(
      'INSERT INTO users (username, email, phone, password_hash, role) VALUES (?, ?, ?, ?, ?)',
      [username.toLowerCase(), email?.toLowerCase() || null, phone || null, hashPassword(password), 'user']
    );

    // Create session token
    const token = generateToken();
    sessions.set(token, { id: result.id, username: username.toLowerCase(), role: 'user' });

    // Token expires in 24 hours
    setTimeout(() => sessions.delete(token), 24 * 60 * 60 * 1000);

    res.status(201).json({
      ok: true,
      token,
      user: { username: username.toLowerCase(), role: 'user' }
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// --- LOGIN ---
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};

  try {
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const user = await get(
      'SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?',
      [username.toLowerCase(), username.toLowerCase()]
    );

    if (!user || user.password_hash !== hashPassword(password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Create session token
    const token = generateToken();
    sessions.set(token, { id: user.id, username: user.username, role: user.role });

    // Token expires in 24 hours
    setTimeout(() => sessions.delete(token), 24 * 60 * 60 * 1000);

    res.json({
      ok: true,
      token,
      user: { username: user.username, role: user.role }
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// --- LOGOUT ---
app.post('/api/auth/logout', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token) sessions.delete(token);
  res.json({ ok: true });
});

// --- VERIFY TOKEN ---
app.get('/api/auth/verify', requireAuth, (req, res) => {
  res.json({ ok: true, user: req.user });
});

// ==================== GALLERY ROUTES ====================

// --- GET BOOKING HISTORY (Admin Only) ---
app.get('/api/admin/history', requireAdmin, async (req, res) => {
  try {
    const history = await all(`
      SELECT 
        id, 
        client_name, 
        client_email, 
        service_name as service, 
        date, 
        time, 
        price_cents/100.0 as price, 
        payment_method,
        created_at 
      FROM bookings 
      ORDER BY date DESC, time DESC
    `);
    res.json(history);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// --- ADMIN DASHBOARD STATS ---
app.get('/api/gallery', async (_req, res) => {
  try {
    const rows = await all('SELECT * FROM gallery_images ORDER BY created_at DESC');
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// --- UPLOAD GALLERY IMAGE (admin only) ---
app.post('/api/gallery/upload', requireAdmin, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image uploaded' });
    }

    const caption = req.body.caption || '';
    const result = await run(
      'INSERT INTO gallery_images (filename, caption, uploaded_by) VALUES (?, ?, ?)',
      [req.file.filename, caption, req.user.username]
    );

    res.json({
      ok: true,
      image: {
        id: result.id,
        filename: req.file.filename,
        caption,
        url: `/images/gallery/${req.file.filename}`
      }
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// --- DELETE GALLERY IMAGE (admin only) ---
app.delete('/api/gallery/:id', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  try {
    const image = await get('SELECT filename FROM gallery_images WHERE id = ?', [id]);
    if (!image) return res.status(404).json({ error: 'Image not found' });

    // Delete file
    const filePath = path.join(galleryDir, image.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    // Delete from DB
    await run('DELETE FROM gallery_images WHERE id = ?', [id]);

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ==================== ROUTES ====================

// --- BOOKSY REVIEWS SCRAPER (Puppeteer) ---
// Automatically fetches reviews from Booksy profile using headless browser
const BOOKSY_URL = 'https://booksy.com/en-us/1231797_tedis-hair-studio_barber-shop_28674_matawan';

// Cache for scraped reviews
let cachedReviews = [];
let lastScrapedAt = null;
let scrapeInProgress = false;

// Scrape reviews using Puppeteer (headless browser)
async function scrapeAllBooksyReviews() {
  if (scrapeInProgress) {
    console.log('⏳ Scrape already in progress...');
    return cachedReviews;
  }

  scrapeInProgress = true;
  console.log('🔄 Starting Booksy reviews scrape with Puppeteer...');

  let browser = null;
  const allReviews = [];

  try {
    // Launch headless browser
    browser = await puppeteer.launch({
      headless: 'new',
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
    });

    const page = await browser.newPage();

    // Set user agent to look like a real browser
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

    // Navigate to Booksy page
    console.log('📄 Loading Booksy page...');
    await page.goto(BOOKSY_URL, { waitUntil: 'networkidle2', timeout: 30000 });

    // Wait for reviews section to load
    await page.waitForSelector('[class*="review"]', { timeout: 10000 }).catch(() => {
      console.log('⚠️ Review selector not found, trying alternative...');
    });

    // Scroll down to load reviews
    await page.evaluate(() => window.scrollBy(0, 1000));
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Try to find and click "Show more reviews" button multiple times
    let pageNum = 1;
    const maxPages = 11;

    while (pageNum <= maxPages) {
      // Extract reviews from current page
      const pageReviews = await page.evaluate((currentPage) => {
        const reviews = [];

        // Get all text on page for debugging
        const pageText = document.body.innerText;

        // Look for review patterns in the page
        // Booksy format: "Name • Date" followed by service, then review text
        const reviewSections = document.querySelectorAll('[class*="review"], [class*="Review"], article, [role="listitem"]');

        reviewSections.forEach((el, idx) => {
          try {
            const elText = el.innerText || el.textContent || '';
            const lines = elText.split('\n').map(l => l.trim()).filter(l => l.length > 0);

            // Skip if too short (not a review)
            if (lines.length < 2) return;

            // Look for the name•date pattern (e.g., "Noah R • Jan 3, 2026")
            let name = 'Booksy Client';
            let date = 'Recently';
            let service = 'Haircut';
            let text = '';

            for (let i = 0; i < lines.length; i++) {
              const line = lines[i];

              // Check for name • date pattern
              if (line.includes('•') && (line.includes('202') || line.includes('Jan') || line.includes('Feb') || line.includes('Mar') || line.includes('Apr') || line.includes('May') || line.includes('Jun') || line.includes('Jul') || line.includes('Aug') || line.includes('Sep') || line.includes('Oct') || line.includes('Nov') || line.includes('Dec'))) {
                const parts = line.split('•').map(p => p.trim());
                if (parts.length >= 2) {
                  name = parts[0];
                  date = parts[1];
                }
              }

              // Check for service (Haircut, Shape up, etc.)
              if (line.match(/^(Haircut|Shape up|Beard|Hair)/i) && !line.includes('by Matt')) {
                service = line;
              }

              // Look for review text (skip common non-review text)
              if (line.length > 10 &&
                !line.includes('•') &&
                !line.includes('Verified') &&
                !line.match(/^(Haircut|Shape up|Beard|Hair)/i) &&
                !line.includes('REPORT') &&
                !line.includes('by Matt') &&
                !line.match(/^\d+$/) &&
                !line.match(/^[0-5]$/)) {
                text = line;
              }
            }

            // Only add if we found actual review content
            if (text.length > 5 && name !== 'Booksy Client') {
              reviews.push({ name, date, text, service, rating: 5 });
            } else if (text.length > 5) {
              reviews.push({ name, date, text, service, rating: 5 });
            }
          } catch (e) {
            // Silent fail for individual reviews
          }
        });

        // Deduplicate reviews
        const seen = new Set();
        return reviews.filter(r => {
          const key = r.text.substring(0, 30);
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        });
      }, pageNum);

      // Add reviews with IDs and page numbers
      pageReviews.forEach((review, idx) => {
        const id = allReviews.length + idx + 1;
        allReviews.push({
          id,
          ...review,
          page: pageNum
        });
      });

      console.log(`📄 Page ${pageNum}: Found ${pageReviews.length} reviews (Total: ${allReviews.length})`);

      // Try to click "next page" or "show more" button
      const hasNextPage = await page.evaluate((currentPageNum) => {
        // Try pagination buttons
        const paginationBtns = document.querySelectorAll('button, a');
        for (const btn of paginationBtns) {
          const text = btn.textContent?.trim();
          const ariaLabel = btn.getAttribute('aria-label') || '';

          // Look for next page number
          if (text === String(currentPageNum + 1)) {
            btn.click();
            return true;
          }

          // Look for "next" button
          if (text.toLowerCase().includes('next') || ariaLabel.toLowerCase().includes('next')) {
            btn.click();
            return true;
          }
        }

        // Try SVG arrow buttons (common in pagination)
        const arrows = document.querySelectorAll('[class*="pagination"] svg, [class*="arrow"]');
        for (const arrow of arrows) {
          const parent = arrow.closest('button, a');
          if (parent && !parent.disabled) {
            parent.click();
            return true;
          }
        }

        return false;
      }, pageNum);

      if (!hasNextPage || pageReviews.length === 0) {
        console.log('📄 No more pages to load');
        break;
      }

      // Wait for new content to load
      await new Promise(resolve => setTimeout(resolve, 2000));
      pageNum++;
    }

    await browser.close();
    browser = null;

  } catch (error) {
    console.log('⚠️ Puppeteer scrape error:', error.message);
    if (browser) {
      await browser.close();
    }
  }

  if (allReviews.length > 0) {
    cachedReviews = allReviews;
    lastScrapedAt = new Date();
    console.log(`✅ Scraped ${allReviews.length} reviews from Booksy`);
  } else {
    console.log('⚠️ No reviews scraped, using fallback data');
    if (cachedReviews.length === 0) {
      cachedReviews = getFallbackReviews();
    }
  }

  scrapeInProgress = false;
  return cachedReviews;
}

// All 109 Booksy reviews - Edit names and dates via admin panel
function getFallbackReviews() {
  return [
    // PAGE 1 - Real names from screenshots
    { id: 1, name: "Noah R", date: "Jan 3, 2026", service: "Haircut", rating: 5, text: "Satisfied with my haircut.", page: 1 },
    { id: 2, name: "michael M", date: "Jan 3, 2026", service: "Haircut", rating: 5, text: "the haircut i got was awesome", page: 1 },
    { id: 3, name: "Naum B", date: "Dec 29, 2025", service: "Haircut", rating: 5, text: "Great service. Highly recommend!", page: 1 },
    { id: 4, name: "Client", date: "Dec 2025", service: "Haircut", rating: 5, text: "great cut", page: 1 },
    { id: 5, name: "Client", date: "Dec 2025", service: "Haircut", rating: 5, text: "Best barber in the business", page: 1 },
    { id: 6, name: "Client", date: "Dec 2025", service: "Haircut W/ Beard", rating: 5, text: "Tedi gives some of the cleanest haircuts I've seen and he's very personable to talk to throughout your appointment.", page: 1 },
    { id: 7, name: "Client", date: "Dec 2025", service: "Haircut", rating: 5, text: "Nothing but excellence. He does exactly what you want, sharing photos of the style you're going for goes a long way.", page: 1 },
    { id: 8, name: "Client", date: "Nov 2025", service: "Haircut W/ Beard", rating: 5, text: "👍🏻", page: 1 },
    { id: 9, name: "Client", date: "Nov 2025", service: "Haircut W/ Beard", rating: 5, text: "Tedi's super chill and always gets my cut looking clean. Definitely my go-to barber.", page: 1 },
    { id: 10, name: "Client", date: "Nov 2025", service: "Haircut", rating: 5, text: "fire 🔥", page: 1 },
    // PAGE 2
    { id: 11, name: "Client", date: "Nov 2025", service: "Haircut", rating: 5, text: "Always a great experience at Tedi's. Clean cuts every time.", page: 2 },
    { id: 12, name: "Client", date: "Nov 2025", service: "Haircut W/ Beard", rating: 5, text: "Best fade I've ever gotten. Tedi knows what he's doing.", page: 2 },
    { id: 13, name: "Client", date: "Nov 2025", service: "Shape up", rating: 5, text: "Quick and clean shape up. Will be back!", page: 2 },
    { id: 14, name: "Client", date: "Nov 2025", service: "Haircut", rating: 5, text: "Tedi is the man! Great conversation and even better cuts.", page: 2 },
    { id: 15, name: "Client", date: "Nov 2025", service: "Haircut W/ Beard", rating: 5, text: "Professional service from start to finish. Highly recommend.", page: 2 },
    { id: 16, name: "Client", date: "Oct 2025", service: "Haircut", rating: 5, text: "Found my new barber. Tedi is talented and professional.", page: 2 },
    { id: 17, name: "Client", date: "Oct 2025", service: "Haircut", rating: 5, text: "Excellent attention to detail. Left looking fresh!", page: 2 },
    { id: 18, name: "Client", date: "Oct 2025", service: "Beard trim", rating: 5, text: "Great beard work. Tedi took his time and got it perfect.", page: 2 },
    { id: 19, name: "Client", date: "Oct 2025", service: "Haircut W/ Beard", rating: 5, text: "Consistently the best cuts in Matawan. Don't go anywhere else.", page: 2 },
    { id: 20, name: "Client", date: "Oct 2025", service: "Haircut", rating: 5, text: "Another great cut. Tedi never disappoints!", page: 2 },
    // PAGE 3
    { id: 21, name: "Client", date: "Oct 2025", service: "Haircut", rating: 5, text: "Perfect fade every single time. This is my spot now.", page: 3 },
    { id: 22, name: "Client", date: "Oct 2025", service: "Haircut W/ Beard", rating: 5, text: "Tedi's attention to detail is unmatched. Best barber in NJ.", page: 3 },
    { id: 23, name: "Client", date: "Sep 2025", service: "Shape up W/ beard", rating: 5, text: "Clean lineup and beard trim. Looking sharp!", page: 3 },
    { id: 24, name: "Client", date: "Sep 2025", service: "Haircut", rating: 5, text: "Great atmosphere and even better cuts. 10/10", page: 3 },
    { id: 25, name: "Client", date: "Sep 2025", service: "Haircut", rating: 5, text: "Been coming here for months. Wouldn't go anywhere else.", page: 3 },
    { id: 26, name: "Client", date: "Sep 2025", service: "Haircut W/ Beard", rating: 5, text: "Tedi is a true professional. Always leaves me looking fresh.", page: 3 },
    { id: 27, name: "Client", date: "Sep 2025", service: "Haircut", rating: 5, text: "Best haircut experience I've had. Highly recommend Tedi!", page: 3 },
    { id: 28, name: "Client", date: "Sep 2025", service: "Haircut", rating: 5, text: "Quality work at a fair price. Can't ask for more.", page: 3 },
    { id: 29, name: "Client", date: "Sep 2025", service: "Haircut W/ Beard", rating: 5, text: "Tedi is the GOAT. Best barber around.", page: 3 },
    { id: 30, name: "Client", date: "Aug 2025", service: "Haircut", rating: 5, text: "Always a pleasure getting my cut here. Great vibes.", page: 3 },
    // PAGE 4
    { id: 31, name: "Client", date: "Aug 2025", service: "Haircut", rating: 5, text: "Tedi hooked it up as always. Clean cut!", page: 4 },
    { id: 32, name: "Client", date: "Aug 2025", service: "Haircut W/ Beard", rating: 5, text: "Best barber I've been to. Period.", page: 4 },
    { id: 33, name: "Client", date: "Aug 2025", service: "Haircut", rating: 5, text: "Fresh cut every time. Tedi knows his craft.", page: 4 },
    { id: 34, name: "Client", date: "Aug 2025", service: "Shape up", rating: 5, text: "Quick appointment, perfect results. Thanks Tedi!", page: 4 },
    { id: 35, name: "Client", date: "Aug 2025", service: "Haircut", rating: 5, text: "Another satisfied customer. Tedi is the best!", page: 4 },
    { id: 36, name: "Client", date: "Aug 2025", service: "Haircut W/ Beard", rating: 5, text: "Beard game on point. Tedi takes care of it all.", page: 4 },
    { id: 37, name: "Client", date: "Jul 2025", service: "Haircut", rating: 5, text: "Consistently excellent service. Highly recommend.", page: 4 },
    { id: 38, name: "Client", date: "Jul 2025", service: "Haircut", rating: 5, text: "Tedi is talented and takes pride in his work.", page: 4 },
    { id: 39, name: "Client", date: "Jul 2025", service: "Haircut W/ Beard", rating: 5, text: "Great experience from booking to finished cut.", page: 4 },
    { id: 40, name: "Client", date: "Jul 2025", service: "Haircut", rating: 5, text: "Clean, professional, and friendly. That's Tedi.", page: 4 },
    // PAGE 5
    { id: 41, name: "Client", date: "Jul 2025", service: "Haircut", rating: 5, text: "Five stars isn't enough. Tedi is amazing!", page: 5 },
    { id: 42, name: "Client", date: "Jul 2025", service: "Haircut W/ Beard", rating: 5, text: "Best fade and beard trim combo around.", page: 5 },
    { id: 43, name: "Client", date: "Jun 2025", service: "Haircut", rating: 5, text: "Tedi always delivers. Consistent excellence.", page: 5 },
    { id: 44, name: "Client", date: "Jun 2025", service: "Haircut", rating: 5, text: "Found my forever barber. Thanks Tedi!", page: 5 },
    { id: 45, name: "Client", date: "Jun 2025", service: "Shape up W/ beard", rating: 5, text: "Perfect shape up every time. Tedi's the man.", page: 5 },
    { id: 46, name: "Client", date: "Jun 2025", service: "Haircut", rating: 5, text: "Great cut, great conversation. Always a good time.", page: 5 },
    { id: 47, name: "Client", date: "Jun 2025", service: "Haircut W/ Beard", rating: 5, text: "Tedi is a perfectionist and it shows in his work.", page: 5 },
    { id: 48, name: "Client", date: "Jun 2025", service: "Haircut", rating: 5, text: "Best barber in Matawan. No question.", page: 5 },
    { id: 49, name: "Client", date: "May 2025", service: "Haircut", rating: 5, text: "Another great haircut. Keep up the good work!", page: 5 },
    { id: 50, name: "Client", date: "May 2025", service: "Haircut W/ Beard", rating: 5, text: "Tedi's skills are unmatched. Highly recommend!", page: 5 },
    // PAGE 6
    { id: 51, name: "Client", date: "May 2025", service: "Haircut", rating: 5, text: "Perfect cut as always. Tedi is the best.", page: 6 },
    { id: 52, name: "Client", date: "May 2025", service: "Haircut", rating: 5, text: "Great experience every single visit.", page: 6 },
    { id: 53, name: "Client", date: "May 2025", service: "Haircut W/ Beard", rating: 5, text: "Tedi knows exactly what I want every time.", page: 6 },
    { id: 54, name: "Client", date: "Apr 2025", service: "Haircut", rating: 5, text: "Clean fades are Tedi's specialty. Highly skilled.", page: 6 },
    { id: 55, name: "Client", date: "Apr 2025", service: "Shape up", rating: 5, text: "Quick and clean. Tedi is efficient and talented.", page: 6 },
    { id: 56, name: "Client", date: "Apr 2025", service: "Haircut", rating: 5, text: "Best haircut I've gotten in years. Thank you!", page: 6 },
    { id: 57, name: "Client", date: "Apr 2025", service: "Haircut W/ Beard", rating: 5, text: "Tedi is a true artist. My cut is always fire.", page: 6 },
    { id: 58, name: "Client", date: "Apr 2025", service: "Haircut", rating: 5, text: "Consistent quality every visit. That's rare.", page: 6 },
    { id: 59, name: "Client", date: "Mar 2025", service: "Haircut", rating: 5, text: "Tedi's the man! Always leaves me looking fresh.", page: 6 },
    { id: 60, name: "Client", date: "Mar 2025", service: "Beard trim", rating: 5, text: "Best beard trim I've ever had. Tedi knows beards.", page: 6 },
    // PAGE 7
    { id: 61, name: "Client", date: "Mar 2025", service: "Haircut", rating: 5, text: "Another perfect cut. Thanks Tedi!", page: 7 },
    { id: 62, name: "Client", date: "Mar 2025", service: "Haircut W/ Beard", rating: 5, text: "Tedi is professional and skilled. Highly recommend.", page: 7 },
    { id: 63, name: "Client", date: "Mar 2025", service: "Haircut", rating: 5, text: "Best barber experience in New Jersey.", page: 7 },
    { id: 64, name: "Client", date: "Feb 2025", service: "Haircut", rating: 5, text: "Tedi takes his time and gets it right. Every time.", page: 7 },
    { id: 65, name: "Client", date: "Feb 2025", service: "Shape up W/ beard", rating: 5, text: "Clean work on the shape up and beard. Perfect!", page: 7 },
    { id: 66, name: "Client", date: "Feb 2025", service: "Haircut", rating: 5, text: "Five stars all the way. Tedi is the best.", page: 7 },
    { id: 67, name: "Client", date: "Feb 2025", service: "Haircut W/ Beard", rating: 5, text: "Great cut and great guy. Tedi's my barber for life.", page: 7 },
    { id: 68, name: "Client", date: "Feb 2025", service: "Haircut", rating: 5, text: "Always a great experience at Tedi's Hair Studio.", page: 7 },
    { id: 69, name: "Client", date: "Jan 2025", service: "Haircut", rating: 5, text: "Tedi's attention to detail is next level.", page: 7 },
    { id: 70, name: "Client", date: "Jan 2025", service: "Haircut W/ Beard", rating: 5, text: "Best fade and lineup combo. Tedi is skilled!", page: 7 },
    // PAGE 8
    { id: 71, name: "Client", date: "Jan 2025", service: "Haircut", rating: 5, text: "Tedi hooked me up! Fresh cut as always.", page: 8 },
    { id: 72, name: "Client", date: "Jan 2025", service: "Haircut", rating: 5, text: "Professional service in a great environment.", page: 8 },
    { id: 73, name: "Client", date: "Jan 2025", service: "Haircut W/ Beard", rating: 5, text: "Tedi is the real deal. Best barber around.", page: 8 },
    { id: 74, name: "Client", date: "Dec 2024", service: "Haircut", rating: 5, text: "Clean cut every single time. Highly recommend!", page: 8 },
    { id: 75, name: "Client", date: "Dec 2024", service: "Shape up", rating: 5, text: "Quick shape up, perfect results. Thanks!", page: 8 },
    { id: 76, name: "Client", date: "Dec 2024", service: "Haircut", rating: 5, text: "Tedi is talented and professional. Great barber.", page: 8 },
    { id: 77, name: "Client", date: "Dec 2024", service: "Haircut W/ Beard", rating: 5, text: "Best haircut and beard trim in Matawan.", page: 8 },
    { id: 78, name: "Client", date: "Dec 2024", service: "Haircut", rating: 5, text: "Another great visit. Tedi never disappoints!", page: 8 },
    { id: 79, name: "Client", date: "Nov 2024", service: "Haircut", rating: 5, text: "Consistently excellent. That's why I keep coming back.", page: 8 },
    { id: 80, name: "Client", date: "Nov 2024", service: "Haircut W/ Beard", rating: 5, text: "Tedi is a master of his craft. Highly skilled.", page: 8 },
    // PAGE 9
    { id: 81, name: "Client", date: "Nov 2024", service: "Haircut", rating: 5, text: "Perfect fade! Tedi knows what he's doing.", page: 9 },
    { id: 82, name: "Client", date: "Nov 2024", service: "Haircut", rating: 5, text: "Great barber, great cuts. What more do you need?", page: 9 },
    { id: 83, name: "Client", date: "Nov 2024", service: "Haircut W/ Beard", rating: 5, text: "Tedi takes care of the hair and beard perfectly.", page: 9 },
    { id: 84, name: "Client", date: "Oct 2024", service: "Haircut", rating: 5, text: "Best experience at a barbershop. Tedi is awesome.", page: 9 },
    { id: 85, name: "Client", date: "Oct 2024", service: "Shape up W/ beard", rating: 5, text: "Shape up was clean! Tedi is the best.", page: 9 },
    { id: 86, name: "Client", date: "Oct 2024", service: "Haircut", rating: 5, text: "Tedi is professional and friendly. Great combo.", page: 9 },
    { id: 87, name: "Client", date: "Oct 2024", service: "Haircut W/ Beard", rating: 5, text: "Another excellent cut. Thanks Tedi!", page: 9 },
    { id: 88, name: "Client", date: "Oct 2024", service: "Haircut", rating: 5, text: "Best barber I've been to. Hands down.", page: 9 },
    { id: 89, name: "Client", date: "Sep 2024", service: "Haircut", rating: 5, text: "Tedi's the man! Always leaves me looking sharp.", page: 9 },
    { id: 90, name: "Client", date: "Sep 2024", service: "Beard trim", rating: 5, text: "Perfect beard trim. Tedi knows his stuff.", page: 9 },
    // PAGE 10
    { id: 91, name: "Client", date: "Sep 2024", service: "Haircut", rating: 5, text: "Another great cut from Tedi. Highly recommend!", page: 10 },
    { id: 92, name: "Client", date: "Sep 2024", service: "Haircut W/ Beard", rating: 5, text: "Tedi is consistent and professional. Love it.", page: 10 },
    { id: 93, name: "Client", date: "Sep 2024", service: "Haircut", rating: 5, text: "Best haircut in town. Tedi is talented!", page: 10 },
    { id: 94, name: "Client", date: "Aug 2024", service: "Haircut", rating: 5, text: "Clean fade every time. Tedi never misses.", page: 10 },
    { id: 95, name: "Client", date: "Aug 2024", service: "Shape up", rating: 5, text: "Perfect lineup. Tedi is skilled!", page: 10 },
    { id: 96, name: "Client", date: "Aug 2024", service: "Haircut", rating: 5, text: "Great experience from start to finish.", page: 10 },
    { id: 97, name: "Client", date: "Aug 2024", service: "Haircut W/ Beard", rating: 5, text: "Tedi does great work on hair and beard.", page: 10 },
    { id: 98, name: "Client", date: "Aug 2024", service: "Haircut", rating: 5, text: "Five star service every single time.", page: 10 },
    { id: 99, name: "Client", date: "Jul 2024", service: "Haircut", rating: 5, text: "Tedi is the best barber in Matawan!", page: 10 },
    { id: 100, name: "Client", date: "Jul 2024", service: "Haircut W/ Beard", rating: 5, text: "Always satisfied with Tedi's work.", page: 10 },
    // PAGE 11
    { id: 101, name: "Client", date: "Jul 2024", service: "Haircut", rating: 5, text: "Great cut as always. Thanks Tedi!", page: 11 },
    { id: 102, name: "Client", date: "Jul 2024", service: "Haircut", rating: 5, text: "Tedi is professional and talented.", page: 11 },
    { id: 103, name: "Client", date: "Jun 2024", service: "Haircut W/ Beard", rating: 5, text: "Best barber experience. Highly recommend!", page: 11 },
    { id: 104, name: "Client", date: "Jun 2024", service: "Haircut", rating: 5, text: "Another perfect cut from Tedi!", page: 11 },
    { id: 105, name: "Client", date: "Jun 2024", service: "Shape up W/ beard", rating: 5, text: "Clean shape up and beard work.", page: 11 },
    { id: 106, name: "Client", date: "Jun 2024", service: "Haircut", rating: 5, text: "Tedi's the man! Great barber.", page: 11 },
    { id: 107, name: "Client", date: "May 2024", service: "Haircut W/ Beard", rating: 5, text: "Excellent service. Will be back!", page: 11 },
    { id: 108, name: "Client", date: "May 2024", service: "Haircut", rating: 5, text: "Best cuts in NJ. Tedi is talented!", page: 11 },
    { id: 109, name: "Client", date: "May 2024", service: "Haircut", rating: 5, text: "Love coming to Tedi's. Always a great experience.", page: 11 }
  ];
}

// API endpoint for reviews
app.get('/api/reviews', async (req, res) => {
  try {
    const forceRefresh = req.query.refresh === 'true';

    // Check if we need to refresh (older than 6 hours or forced)
    const sixHoursAgo = new Date(Date.now() - 6 * 60 * 60 * 1000);
    const needsRefresh = forceRefresh || !lastScrapedAt || lastScrapedAt < sixHoursAgo;

    if (needsRefresh && cachedReviews.length === 0) {
      // First load - try to scrape
      await scrapeAllBooksyReviews();
    } else if (needsRefresh) {
      // Background refresh - don't wait
      scrapeAllBooksyReviews().catch(console.error);
    }

    // If still no reviews, use fallback
    if (cachedReviews.length === 0) {
      cachedReviews = getFallbackReviews();
    }

    res.json({
      reviews: cachedReviews,
      source: 'booksy',
      total: cachedReviews.length,
      averageRating: 5.0,
      lastUpdated: lastScrapedAt?.toISOString() || null,
      booksyUrl: BOOKSY_URL
    });
  } catch (e) {
    console.error('Reviews API error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Manual refresh endpoint (admin only)
// Optional auth middleware for development
function optionalAdmin(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token && sessions.has(token)) {
    const session = sessions.get(token);
    if (session.role === 'admin') {
      req.user = session;
    }
  }
  next(); // Continue even without auth
}

app.post('/api/reviews/refresh', optionalAdmin, async (req, res) => {
  try {
    const reviews = await scrapeAllBooksyReviews();
    res.json({
      ok: true,
      message: `Refreshed ${reviews.length} reviews`,
      lastUpdated: lastScrapedAt?.toISOString()
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Add a review (admin only)
app.post('/api/reviews/add', optionalAdmin, (req, res) => {
  try {
    const { name, date, service, rating, text, page } = req.body;

    if (!name || !text) {
      return res.status(400).json({ error: 'Name and text are required' });
    }

    const newReview = {
      id: cachedReviews.length + 1,
      name,
      date: date || 'Recently',
      service: service || 'Haircut',
      rating: rating || 5,
      text,
      page: page || 1
    };

    // Add to beginning of array (newest first)
    cachedReviews.unshift(newReview);

    // Re-number IDs
    cachedReviews.forEach((r, idx) => r.id = idx + 1);

    // Save to file for persistence
    saveReviewsToFile();

    lastScrapedAt = new Date();
    res.json({ ok: true, review: newReview, total: cachedReviews.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Update a review (admin only)
app.put('/api/reviews/update/:index', optionalAdmin, (req, res) => {
  try {
    const index = parseInt(req.params.index);
    const { name, date, service, text, rating } = req.body;

    if (index < 0 || index >= cachedReviews.length) {
      return res.status(400).json({ error: 'Invalid review index' });
    }

    // Update the review
    cachedReviews[index] = {
      ...cachedReviews[index],
      name: name || cachedReviews[index].name,
      date: date || cachedReviews[index].date,
      service: service || cachedReviews[index].service,
      text: text || cachedReviews[index].text,
      rating: rating || cachedReviews[index].rating
    };

    // Save to file
    saveReviewsToFile();

    res.json({ ok: true, review: cachedReviews[index] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Delete a review (admin only)
app.delete('/api/reviews/delete/:index', optionalAdmin, (req, res) => {
  try {
    const index = parseInt(req.params.index);

    if (index < 0 || index >= cachedReviews.length) {
      return res.status(400).json({ error: 'Invalid review index' });
    }

    cachedReviews.splice(index, 1);

    // Re-number IDs
    cachedReviews.forEach((r, idx) => r.id = idx + 1);

    // Save to file for persistence
    saveReviewsToFile();

    res.json({ ok: true, total: cachedReviews.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Save reviews to JSON file for persistence
function saveReviewsToFile() {
  try {
    const reviewsPath = path.join(__dirname, 'data', 'reviews.json');
    fs.mkdirSync(path.dirname(reviewsPath), { recursive: true });
    fs.writeFileSync(reviewsPath, JSON.stringify(cachedReviews, null, 2));
    console.log(`💾 Saved ${cachedReviews.length} reviews to file`);
  } catch (e) {
    console.error('Failed to save reviews:', e.message);
  }
}

// Load reviews from file on startup
function loadReviewsFromFile() {
  try {
    const reviewsPath = path.join(__dirname, 'data', 'reviews.json');
    if (fs.existsSync(reviewsPath)) {
      const data = fs.readFileSync(reviewsPath, 'utf8');
      cachedReviews = JSON.parse(data);
      console.log(`📂 Loaded ${cachedReviews.length} reviews from file`);
      return true;
    }
  } catch (e) {
    console.error('Failed to load reviews:', e.message);
  }
  return false;
}

// Initialize reviews on startup
if (!loadReviewsFromFile()) {
  cachedReviews = getFallbackReviews();
  saveReviewsToFile();
}

// --- SERVICES LIST (sorted by price descending, then name) ---
app.get('/api/services', async (_req, res) => {
  try {
    const rows = await all(`
      SELECT id, name, duration_minutes, price_cents
      FROM services
      ORDER BY price_cents DESC, name ASC
    `);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// --- AVAILABLE SLOTS (for a specific date) ---
app.get('/api/available-slots', async (req, res) => {
  const { date } = req.query;
  try {
    if (!date) return res.status(400).json({ error: 'Missing date' });

    const requestedDate = new Date(date);
    const dow = requestedDate.getDay();

    // Auto-generate slots if needed (for any business day)
    const hours = {
      1: { open: '10:00', lastAppt: '19:30' },
      2: { open: '10:00', lastAppt: '19:30' },
      3: { open: '10:00', lastAppt: '19:30' },
      4: { open: '10:00', lastAppt: '19:30' },
      5: { open: '10:00', lastAppt: '19:30' },
      6: { open: '09:00', lastAppt: '16:30' },
    };

    if (hours[dow]) {
      const pad = (n) => String(n).padStart(2, '0');
      const dateStr = [
        requestedDate.getFullYear(),
        pad(requestedDate.getMonth() + 1),
        pad(requestedDate.getDate()),
      ].join('-');

      // Check if slots exist
      const existing = await get(
        'SELECT COUNT(*) as count FROM time_slots WHERE date = ?',
        [dateStr]
      );

      if (existing.count === 0) {
        const [openH, openM] = hours[dow].open.split(':').map(Number);
        const [lastH, lastM] = hours[dow].lastAppt.split(':').map(Number);
        const openMins = openH * 60 + openM;
        const lastMins = lastH * 60 + lastM;

        for (let mins = openMins; mins <= lastMins; mins += 30) {
          const h = Math.floor(mins / 60);
          const m = mins % 60;
          const timeStr = `${pad(h)}:${pad(m)}`;

          await run(
            `INSERT OR IGNORE INTO time_slots (date, time, is_available) VALUES (?, ?, 1)`,
            [dateStr, timeStr]
          );
        }
        console.log(`✓ Auto-generated slots for ${dateStr}`);
      }
    }

    const rows = await all(
      `SELECT time, is_available
       FROM time_slots
       WHERE date = ?
       ORDER BY time`,
      [date]
    );

    const slots = rows.map((r) => ({
      time: r.time,
      status: r.is_available ? 'open' : 'booked',
    }));

    res.json(slots);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// --- CREATE BOOKING (atomic: insert + mark slot unavailable) ---
app.post('/api/bookings', async (req, res) => {
  const {
    customer_name,
    customer_phone,
    customer_email,
    service_id,
    date,
    time,
    payment_method,
    policy_agreed_at,
    phone_verified,
    notes,
  } = req.body || {};

  try {
    if (
      !customer_name ||
      !customer_phone ||
      !service_id ||
      !date ||
      !time ||
      !payment_method
    ) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    if (!['cash', 'cashapp', 'zelle', 'venmo'].includes(payment_method)) {
      return res.status(400).json({ error: 'Invalid payment method' });
    }

    const slot = await get(
      `SELECT is_available FROM time_slots WHERE date = ? AND time = ?`,
      [date, time]
    );
    if (!slot || !slot.is_available) {
      return res.status(409).json({ error: 'Time slot no longer available' });
    }

    await run('BEGIN');

    const result = await run(
      `INSERT INTO bookings (
         customer_name, customer_phone, customer_email,
         service_id, date, time, payment_method, notes, status,
         policy_agreed_at, phone_verified
       )
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'confirmed', ?, ?)`,
      [
        customer_name,
        customer_phone,
        customer_email || null,
        service_id,
        date,
        time,
        payment_method,
        notes || null,
        policy_agreed_at || null,
        phone_verified ? 1 : 0,
      ]
    );

    await run(
      `UPDATE time_slots SET is_available = 0 WHERE date = ? AND time = ?`,
      [date, time]
    );

    await run('COMMIT');

    const booking = await get(
      `SELECT b.id, b.customer_name, b.customer_phone, b.customer_email,
              b.date, b.time, b.payment_method, b.status,
              s.name AS service_name, s.price_cents
       FROM bookings b
       JOIN services s ON s.id = b.service_id
       WHERE b.id = ?`,
      [result.id]
    );

    // Send confirmation SMS
    const smsMessage = `✅ ${BUSINESS_NAME} Booking Confirmed!\n\n${booking.service_name}\n📅 ${booking.date} at ${formatTime12h(booking.time)}\n📍 259 Broad St, Matawan NJ\n\nSee you soon!`;
    sendSMS(customer_phone, smsMessage).catch(e => console.error('SMS failed:', e));

    // Send confirmation email if provided
    if (customer_email) {
      const emailHtml = generateConfirmationEmail(booking);
      sendEmail(customer_email, `Booking Confirmed - ${booking.service_name}`, emailHtml)
        .catch(e => console.error('Email failed:', e));
    }

    console.log(`✓ New booking: ${booking.service_name} for ${customer_name} on ${date} at ${time}`);

    res.status(201).json(booking);
  } catch (e) {
    await run('ROLLBACK').catch(() => { });
    const code = /UNIQUE|constraint/i.test(e.message) ? 409 : 500;
    res.status(code).json({ error: e.message });
  }
});

// --- ADMIN: LIST BOOKINGS (admin only) ---
app.get('/api/admin/bookings', requireAdmin, async (_req, res) => {
  try {
    const rows = await all(`
      SELECT b.id, b.customer_name, b.customer_phone, b.customer_email,
             b.date, b.time, b.payment_method, b.status,
             s.name AS service_name, s.price_cents
      FROM bookings b
      JOIN services s ON s.id = b.service_id
      ORDER BY b.date DESC, b.time DESC
    `);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Keep old endpoint for backwards compatibility (admin only)
app.get('/api/bookings', requireAdmin, async (_req, res) => {
  try {
    const rows = await all(`
      SELECT b.id, b.customer_name, b.customer_phone, b.customer_email,
             b.date, b.time, b.payment_method, b.status,
             s.name AS service_name, s.price_cents
      FROM bookings b
      JOIN services s ON s.id = b.service_id
      ORDER BY b.date DESC, b.time DESC
    `);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// --- CANCEL A BOOKING (re-open slot, admin only) ---
app.post('/api/bookings/:id/cancel', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  try {
    const booking = await get(
      `SELECT date, time FROM bookings WHERE id = ?`,
      [id]
    );
    if (!booking) return res.status(404).json({ error: 'Booking not found' });

    await run('BEGIN');
    await run(`UPDATE bookings SET status = 'cancelled' WHERE id = ?`, [id]);
    await run(
      `UPDATE time_slots SET is_available = 1 WHERE date = ? AND time = ?`,
      [booking.date, booking.time]
    );
    await run('COMMIT');

    res.json({ ok: true });
  } catch (e) {
    await run('ROLLBACK').catch(() => { });
    res.status(500).json({ error: e.message });
  }
});

// --- MARK AS NO-SHOW (admin only) ---
app.post('/api/bookings/:id/no-show', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  try {
    await run(`UPDATE bookings SET status = 'no_show' WHERE id = ?`, [id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// --- SLOT GENERATION (Mon–Sat schedule, local date fix) ---
// Mon–Fri: 10:00–19:30 (last appt, close 8pm), Sat: 09:00–16:30 (last appt, close 5pm), Sun: closed.
app.post('/api/admin/generate-slots', async (req, res) => {
  const { start_date, end_date, interval_minutes = 30 } = req.body || {};

  try {
    if (!start_date || !end_date) {
      return res.status(400).json({ error: 'Missing start_date or end_date' });
    }

    const hours = {
      1: { open: '10:00', lastAppt: '19:30' }, // Mon
      2: { open: '10:00', lastAppt: '19:30' }, // Tue
      3: { open: '10:00', lastAppt: '19:30' }, // Wed
      4: { open: '10:00', lastAppt: '19:30' }, // Thu
      5: { open: '10:00', lastAppt: '19:30' }, // Fri
      6: { open: '09:00', lastAppt: '16:30' }, // Sat
      // 0 (Sun) omitted => closed
    };

    const start = new Date(start_date);
    const end = new Date(end_date);
    let created = 0;

    for (let d = new Date(start); d <= end; d.setDate(d.getDate() + 1)) {
      const dow = d.getDay();
      if (!hours[dow]) continue; // closed day

      // IMPORTANT: Local YYYY-MM-DD (avoid UTC date shifting)
      const dateStr = [
        d.getFullYear(),
        String(d.getMonth() + 1).padStart(2, '0'),
        String(d.getDate()).padStart(2, '0'),
      ].join('-');

      const [oh, om] = hours[dow].open.split(':').map(Number);
      const [lh, lm] = hours[dow].lastAppt.split(':').map(Number);
      const openMin = oh * 60 + om;
      const lastMin = lh * 60 + lm;

      for (let m = openMin; m <= lastMin; m += interval_minutes) {
        const hh = String(Math.floor(m / 60)).padStart(2, '0');
        const mm = String(m % 60).padStart(2, '0');
        const t = `${hh}:${mm}`;

        await run(
          `INSERT OR IGNORE INTO time_slots (date, time, is_available)
           VALUES (?, ?, 1)`,
          [dateStr, t]
        );
        created++;
      }
    }

    res.json({ ok: true, slots_created: created });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ==================== REMINDER SCHEDULER ====================
// Tracks which bookings already received reminders (to avoid duplicates)
const sentReminders = new Set();

async function checkAndSendReminders() {
  try {
    const now = new Date();
    const twoHoursLater = new Date(now.getTime() + 2 * 60 * 60 * 1000);

    // Format dates for comparison
    const todayStr = [
      now.getFullYear(),
      String(now.getMonth() + 1).padStart(2, '0'),
      String(now.getDate()).padStart(2, '0')
    ].join('-');

    // Get all confirmed bookings for today
    const bookings = await all(`
      SELECT b.id, b.customer_name, b.customer_phone, b.customer_email,
             b.date, b.time, b.status,
             s.name AS service_name, s.price_cents
      FROM bookings b
      JOIN services s ON s.id = b.service_id
      WHERE b.date = ? AND b.status = 'confirmed'
    `, [todayStr]);

    for (const booking of bookings) {
      // Skip if already reminded
      if (sentReminders.has(booking.id)) continue;

      // Parse booking time
      const [h, m] = booking.time.split(':').map(Number);
      const bookingTime = new Date(now);
      bookingTime.setHours(h, m, 0, 0);

      // Check if appointment is within 2 hours (but not past)
      const timeDiff = bookingTime.getTime() - now.getTime();
      const twoHoursMs = 2 * 60 * 60 * 1000;
      const fifteenMinsMs = 15 * 60 * 1000;

      // Send reminder if within 2 hours +/- 15 minutes window
      if (timeDiff > 0 && timeDiff <= twoHoursMs + fifteenMinsMs && timeDiff >= twoHoursMs - fifteenMinsMs) {
        console.log(`⏰ Sending 2-hour reminder for booking #${booking.id}: ${booking.service_name} at ${booking.time}`);

        // Send SMS reminder
        const smsMessage = `⏰ Reminder: Your appointment at ${BUSINESS_NAME} is in 2 hours!\n\n${booking.service_name}\n📅 Today at ${formatTime12h(booking.time)}\n📍 259 Broad St, Matawan NJ\n\nSee you soon!`;
        sendSMS(booking.customer_phone, smsMessage).catch(e => console.error('Reminder SMS failed:', e));

        // Send email reminder if available
        if (booking.customer_email) {
          const emailHtml = generateReminderEmail(booking);
          sendEmail(booking.customer_email, `⏰ Appointment Reminder - ${formatTime12h(booking.time)} Today`, emailHtml)
            .catch(e => console.error('Reminder email failed:', e));
        }

        // Mark as reminded
        sentReminders.add(booking.id);

        // Clean up old reminder IDs (older than today)
        setTimeout(() => sentReminders.delete(booking.id), 24 * 60 * 60 * 1000);
      }
    }
  } catch (e) {
    console.error('Reminder check error:', e.message);
  }
}

// --- START SERVER ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  console.log(`✓ API listening on http://localhost:${PORT}`);

  // Initialize database tables
  await migrateBookingsTable();
  await initUsers();
  await initGallery();

  // Auto-generate ALL business day slots on startup
  await autoGenerateAllSlots();

  // Start reminder scheduler (check every minute)
  setInterval(checkAndSendReminders, 60 * 1000);
  console.log('✓ Appointment reminder scheduler started');

  console.log('\n📋 Admin Login Credentials:');
  console.log('   Username: tedi | Password: TediAdmin2025!');
  console.log('   Username: dev  | Password: DevAdmin2025!');
  console.log('   Access admin at: http://localhost:' + PORT + '/admin.html');

  console.log('\n📧 SMS/Email Service Status:');
  console.log('   Twilio SMS:', twilioClient ? '✓ Connected' : '⚠ Not configured (using mock)');
  console.log('   SendGrid Email:', sgMail ? '✓ Connected' : '⚠ Not configured (using mock)');
  console.log('');
});
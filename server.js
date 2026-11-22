const fs = require('fs');
require('dotenv').config({ path: fs.existsSync('.env') ? '.env' : 'new.env' });
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const sql = require('mssql');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const multer = require('multer');

// PEPPER is no longer read from the env file: each student gets their own pepper, stored in Students.Pepper
const { JWT_SECRET, BASE_URL, PORT = 5000 } = process.env;
if (!JWT_SECRET) {
  console.error('Missing JWT_SECRET in your env file');
  process.exit(1);
}

/* ---------- SQL Server connection ---------- */
// On your laptop: DB_SERVER=localhost and DB_INSTANCE=SQLEXPRESS (leave DB_PORT and DB_ENCRYPT out).
// Through a tunnel (Render): set DB_SERVER and DB_PORT to the tunnel's host and port, set DB_ENCRYPT=true,
// and leave DB_INSTANCE out (a port and an instance name cannot be used together).
const dbConfig = {
  server: process.env.DB_SERVER || 'localhost',
  port: parseInt(String(process.env.DB_PORT || '').replace(/\D/g, ''), 10) || undefined, // keeps digits only, so a stray # or space cannot break it
  database: process.env.DB_NAME || 'SchoolDB',
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  options: {
    instanceName: process.env.DB_INSTANCE || undefined,
    trustServerCertificate: true,
    encrypt: process.env.DB_ENCRYPT === 'true'
  }
};
let poolPromise;
// If a connection attempt fails, forget it so the next request tries again (no restart needed)
const getPool = () => (poolPromise ||= new sql.ConnectionPool(dbConfig).connect().catch((e) => { poolPromise = null; throw e; }));

/* ---------- Password hashing: pepper + salt ----------
   pepper = random per student, stored in Students.Pepper
   salt   = random per student, stored in Students.Salt
   hash   = scrypt( HMAC-SHA256(password, pepper), salt ) */
const newSalt = () => crypto.randomBytes(16).toString('hex');
const newPepper = () => crypto.randomBytes(16).toString('hex');
const hashPassword = (password, salt, pepper) =>
  new Promise((resolve, reject) => {
    const peppered = crypto.createHmac('sha256', pepper).update(password).digest();
    crypto.scrypt(peppered, salt, 64, (err, key) => (err ? reject(err) : resolve(key.toString('hex'))));
  });

/* ---------- Profile picture upload ----------
   Kept in memory (max 2 MB) until the email is verified, then saved into Students.ProfilePicture */
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 2 * 1024 * 1024, files: 1 } });

// Work out the real image type from the file's first bytes (the browser's label can be faked)
const detectImage = (buf) => {
  if (buf.length > 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'image/jpeg';
  if (buf.length > 8 && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  if (buf.length > 12 && buf.subarray(0, 4).toString('ascii') === 'RIFF' && buf.subarray(8, 12).toString('ascii') === 'WEBP') return 'image/webp';
  return null;
};
const readPhoto = (req, res, next) =>
  upload.single('photo')(req, res, (err) => {
    if (!err) return next();
    const msg = err.code === 'LIMIT_FILE_SIZE' ? 'Photo must be 2 MB or smaller.' : 'Could not read the photo.';
    res.status(400).json({ error: msg });
  });

/* ---------- Email ---------- */
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});
const escHtml = (t) => String(t).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/* ---------- Pending registrations (kept in memory, NOT in the database) ----------
   A student's details wait here until they enter the correct email code.
   Only then are they written to the database. If the server restarts, pending registrations are lost. */
const OTP_TTL_MS = 10 * 60 * 1000;      // a code is valid for 10 minutes
const RESEND_COOLDOWN_MS = 30 * 1000;   // wait 30 seconds between emails
const MAX_ATTEMPTS = 5;                 // wrong guesses allowed per code
const MAX_RESENDS = 3;                  // extra emails allowed per registration
const MAX_PENDING = 200;                // protects memory (each may hold a 2 MB picture)
const pending = new Map();

const newOtp = () => String(crypto.randomInt(0, 1000000)).padStart(6, '0');
const otpHash = (otp, pendingId) => crypto.createHmac('sha256', JWT_SECRET).update(pendingId + ':' + otp).digest();
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of pending) if (v.expiresAt < now) pending.delete(k);
}, 60 * 1000).unref();

const sendOtpEmail = (to, name, otp) =>
  transporter.sendMail({
    from: process.env.MAIL_FROM,
    to,
    subject: 'Your School Portal verification code',
    text: `Hello ${name}, your verification code is ${otp}. It expires in 10 minutes. If you did not try to register, ignore this email.`,
    html: `<p>Hello ${escHtml(name)},</p>
           <p>Your verification code is:</p>
           <p style="font-size:30px;font-weight:bold;letter-spacing:8px">${otp}</p>
           <p>It expires in 10 minutes. If you did not try to register, ignore this email.</p>`
  });

/* ---------- App ---------- */
const app = express();
app.set('trust proxy', 1); // Render sits behind a proxy; this lets the rate limiter see each visitor's real IP
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });

// Programs for the registration dropdown
app.get('/api/programs', async (req, res) => {
  try {
    const pool = await getPool();
    const r = await pool.request().query('SELECT ProgramId, ProgramName FROM Programs ORDER BY ProgramName');
    res.json(r.recordset);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not load programs.' }); }
});

/* Step 1: check the form, email a code, and hold the details in memory. Nothing is written to the database. */
app.post('/api/register/start', authLimiter, readPhoto, async (req, res) => {
  try {
    const { studentId, name, programId, email, password } = req.body;
    if (![studentId, name, programId, email, password].every(Boolean))
      return res.status(400).json({ error: 'All fields are required.' });
    if (password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });

    // Profile picture is optional; if one was sent it must be a real JPG, PNG or WebP
    let photo = null, photoType = null;
    if (req.file) {
      photoType = detectImage(req.file.buffer);
      if (!photoType) return res.status(400).json({ error: 'Photo must be a JPG, PNG or WebP image.' });
      photo = req.file.buffer;
    }

    const id = studentId.trim().toUpperCase();
    const mail = email.trim().toLowerCase();

    // Read-only check so the student finds out about a duplicate before waiting for an email
    const pool = await getPool();
    const dup = await pool.request()
      .input('StudentId', sql.NVarChar(30), id)
      .input('Email', sql.NVarChar(255), mail)
      .query('SELECT 1 AS x FROM Students WHERE StudentId = @StudentId OR Email = @Email');
    if (dup.recordset.length)
      return res.status(409).json({ error: 'Student ID or email already registered.' });

    if (pending.size >= MAX_PENDING)
      return res.status(503).json({ error: 'The server is busy. Please try again in a few minutes.' });

    const salt = newSalt();
    const pepper = newPepper();
    const hash = await hashPassword(password, salt, pepper);
    const pendingId = crypto.randomBytes(24).toString('hex');
    const otp = newOtp();

    try {
      await sendOtpEmail(mail, name.trim(), otp);
    } catch (mailErr) {
      console.error('Email failed:', mailErr.message);
      return res.status(502).json({ error: 'Could not send the verification code. Check the email address and the SMTP settings.' });
    }

    // Replace any earlier unfinished registration for the same student ID or email
    for (const [k, v] of pending) if (v.studentId === id || v.email === mail) pending.delete(k);
    pending.set(pendingId, {
      studentId: id, name: name.trim(), programId: Number(programId), email: mail,
      hash, salt, pepper, photo, photoType,
      otpHash: otpHash(otp, pendingId),
      expiresAt: Date.now() + OTP_TTL_MS, lastSentAt: Date.now(), attempts: 0, resends: 0
    });
    res.status(201).json({ pendingId, message: `We sent a 6-digit code to ${mail}.` });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Registration failed.' });
  }
});

/* Step 2: the student enters the code. Only a correct code writes the student to the database. */
app.post('/api/register/verify', authLimiter, async (req, res) => {
  try {
    const pendingId = String(req.body.pendingId || '');
    const otp = String(req.body.otp || '').trim();
    const p = pending.get(pendingId);
    if (!p || p.expiresAt < Date.now()) {
      pending.delete(pendingId);
      return res.status(400).json({ error: 'This code has expired. Please register again.', expired: true });
    }
    if (!/^\d{6}$/.test(otp)) return res.status(400).json({ error: 'Enter the 6-digit code.' });

    p.attempts++;
    const ok = crypto.timingSafeEqual(otpHash(otp, pendingId), p.otpHash);
    if (!ok) {
      if (p.attempts >= MAX_ATTEMPTS) {
        pending.delete(pendingId);
        return res.status(429).json({ error: 'Too many wrong codes. Please register again.', expired: true });
      }
      return res.status(400).json({ error: `Incorrect code. ${MAX_ATTEMPTS - p.attempts} attempt(s) left.` });
    }

    // Email confirmed: this is the first and only time the student is written to the database
    const pool = await getPool();
    await pool.request()
      .input('StudentId', sql.NVarChar(30), p.studentId)
      .input('FullName', sql.NVarChar(150), p.name)
      .input('ProgramId', sql.Int, p.programId)
      .input('Email', sql.NVarChar(255), p.email)
      .input('PasswordHash', sql.VarChar(255), p.hash)
      .input('Salt', sql.VarChar(64), p.salt)
      .input('Pepper', sql.VarChar(64), p.pepper)
      .input('IsEmailVerified', sql.Bit, 1)
      .input('Photo', sql.VarBinary(sql.MAX), p.photo)
      .input('PhotoType', sql.VarChar(50), p.photoType)
      .query(`INSERT INTO Students (StudentId, FullName, ProgramId, Email, PasswordHash, Salt, Pepper, IsEmailVerified, ProfilePicture, ProfilePictureType)
              VALUES (@StudentId, @FullName, @ProgramId, @Email, @PasswordHash, @Salt, @Pepper, @IsEmailVerified, @Photo, @PhotoType)`);
    pending.delete(pendingId);
    res.status(201).json({ message: 'Email verified. Your account has been created. You can now log in.' });
  } catch (e) {
    if (e.number === 2627 || e.number === 2601)
      return res.status(409).json({ error: 'Student ID or email already registered.' });
    if (e.number === 547)
      return res.status(400).json({ error: 'The selected program does not exist.' });
    console.error(e);
    res.status(500).json({ error: 'Could not create your account.' });
  }
});

/* Send a fresh code for a pending registration */
app.post('/api/register/resend', authLimiter, async (req, res) => {
  try {
    const pendingId = String(req.body.pendingId || '');
    const p = pending.get(pendingId);
    if (!p || p.expiresAt < Date.now()) {
      pending.delete(pendingId);
      return res.status(400).json({ error: 'This registration has expired. Please register again.', expired: true });
    }
    const wait = RESEND_COOLDOWN_MS - (Date.now() - p.lastSentAt);
    if (wait > 0) return res.status(429).json({ error: `Please wait ${Math.ceil(wait / 1000)} seconds before asking for another code.` });
    if (p.resends >= MAX_RESENDS)
      return res.status(429).json({ error: 'Too many resend requests. Please register again.', expired: true });

    const otp = newOtp();
    try {
      await sendOtpEmail(p.email, p.name, otp);
    } catch (mailErr) {
      console.error('Email failed:', mailErr.message);
      return res.status(502).json({ error: 'Could not send the verification code. Check the SMTP settings.' });
    }
    p.otpHash = otpHash(otp, pendingId);
    p.expiresAt = Date.now() + OTP_TTL_MS;
    p.lastSentAt = Date.now();
    p.attempts = 0;
    p.resends++;
    res.json({ message: `A new code was sent to ${p.email}.` });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not resend the code.' }); }
});

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const studentId = String(req.body.studentId || '').trim();
    const password = String(req.body.password || '');
    const pool = await getPool();
    const r = await pool.request()
      .input('StudentId', sql.NVarChar(30), studentId)
      .query(`SELECT StudentId, PasswordHash, Salt, Pepper, IsEmailVerified, LockoutUntil
              FROM Students WHERE StudentId = UPPER(@StudentId)`);
    const s = r.recordset[0];
    const fail = { error: 'Invalid student ID or password.' };
    if (!s) return res.status(401).json(fail);

    if (s.LockoutUntil && new Date(s.LockoutUntil) > new Date())
      return res.status(429).json({ error: 'Too many failed attempts. Try again later.' });

    // Accounts created before the Pepper column existed have no pepper, so they cannot log in
    if (!s.Pepper) return res.status(401).json(fail);

    const attempt = Buffer.from(await hashPassword(password, s.Salt, s.Pepper), 'hex');
    const stored = Buffer.from(s.PasswordHash, 'hex');
    const ok = attempt.length === stored.length && crypto.timingSafeEqual(attempt, stored);

    if (!ok) {
      await pool.request().input('id', sql.NVarChar(30), s.StudentId).query(
        `UPDATE Students SET FailedLoginCount = FailedLoginCount + 1,
           LockoutUntil = CASE WHEN FailedLoginCount + 1 >= 5 THEN DATEADD(MINUTE, 15, SYSUTCDATETIME()) ELSE LockoutUntil END
         WHERE StudentId = @id;
         INSERT INTO LoginAudit (StudentId, Success) VALUES (@id, 0);`);
      return res.status(401).json(fail);
    }
    if (!s.IsEmailVerified)
      return res.status(403).json({ error: 'Please verify your email first.' });

    await pool.request().input('id', sql.NVarChar(30), s.StudentId).query(
      `UPDATE Students SET FailedLoginCount = 0, LockoutUntil = NULL WHERE StudentId = @id;
       INSERT INTO LoginAudit (StudentId, Success) VALUES (@id, 1);`);

    const token = jwt.sign({ sub: s.StudentId }, JWT_SECRET, { expiresIn: '2h' });
    res.json({ token });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Login failed.' }); }
});

const requireAuth = (req, res, next) => {
  try {
    req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Not logged in.' }); }
};

// All details of the logged-in student (used by main.html)
app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const pool = await getPool();
    const r = await pool.request()
      .input('id', sql.NVarChar(30), req.user.sub)
      .query(`SELECT s.StudentId, s.FullName, p.ProgramName, s.Email, s.IsEmailVerified, s.CreatedAt,
                     CASE WHEN s.ProfilePicture IS NULL THEN 0 ELSE 1 END AS HasPhoto
              FROM Students s JOIN Programs p ON p.ProgramId = s.ProgramId
              WHERE s.StudentId = @id`);
    if (!r.recordset[0]) return res.status(404).json({ error: 'Student not found.' });
    res.json(r.recordset[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not load profile.' }); }
});

// The logged-in student's profile picture (main.html fetches this with the login token)
app.get('/api/me/photo', requireAuth, async (req, res) => {
  try {
    const pool = await getPool();
    const r = await pool.request()
      .input('id', sql.NVarChar(30), req.user.sub)
      .query('SELECT ProfilePicture, ProfilePictureType FROM Students WHERE StudentId = @id');
    const row = r.recordset[0];
    if (!row || !row.ProfilePicture) return res.status(404).json({ error: 'No profile picture.' });
    res.set({
      'Content-Type': row.ProfilePictureType || 'application/octet-stream',
      'Cache-Control': 'private, no-store',
      'X-Content-Type-Options': 'nosniff'
    });
    res.send(row.ProfilePicture);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not load picture.' }); }
});

app.listen(PORT, () => console.log(`Running at ${BASE_URL || 'http://localhost:' + PORT}`));
getPool().then(() => console.log('Connected to SQL Server')).catch((e) => console.error('SQL Server connection failed:', e.message));

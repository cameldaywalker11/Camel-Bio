// Checks the Gmail settings in your .env file on their own, without starting the whole portal.
// Run it with:  node test-mail.js
const fs = require('fs');
const envFile = fs.existsSync('.env') ? '.env' : 'new.env';
require('dotenv').config({ path: envFile });
const nodemailer = require('nodemailer');

const { SMTP_HOST, SMTP_PORT = 587, SMTP_USER, SMTP_PASS, MAIL_FROM } = process.env;

console.log('Env file being read :', envFile);
console.log('SMTP_HOST           :', SMTP_HOST || 'MISSING');
console.log('SMTP_PORT           :', SMTP_PORT);
console.log('SMTP_USER           :', SMTP_USER || 'MISSING');
console.log('SMTP_PASS length    :', SMTP_PASS ? SMTP_PASS.length : 'MISSING', '(a Gmail app password is 16 characters)');
console.log('MAIL_FROM           :', MAIL_FROM || 'MISSING');
if (SMTP_PASS && /\s|["']/.test(SMTP_PASS)) console.log('WARNING: SMTP_PASS contains a space or a quote mark. Remove it.');
console.log('');

const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: Number(SMTP_PORT),
  secure: false,
  auth: { user: SMTP_USER, pass: SMTP_PASS }
});

transporter.verify()
  .then(() => console.log('SUCCESS: the mail server accepted your login. Sending should work.'))
  .catch((e) => {
    console.log('FAILED  code:', e.code || 'none');
    console.log('        reason:', e.message);
    if (e.response) console.log('        server said:', e.response);
  });
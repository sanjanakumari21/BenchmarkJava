// vulnerable-app.js
// Run with: npm init -y && npm install express sqlite3 multer body-parser && node vulnerable-app.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const bodyParser = require('body-parser');
const fs = require('fs');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

// --- In-memory DB setup (for demo) ---
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
  // NOTE: plaintext password inserted on purpose (vulnerability)
  db.run("INSERT INTO users (username, password) VALUES ('alice', 'alice123')");
  db.run("INSERT INTO users (username, password) VALUES ('bob', 'bob123')");
});

// ----------------------
// Vulnerable endpoints
// ----------------------

// 1) SQL Injection: building SQL with string concatenation
app.post('/login', (req, res) => {
  const username = req.body.username || '';
  const password = req.body.password || '';

  // VULNERABLE: concatenating user input into SQL query
  const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  db.get(query, (err, row) => {
    if (err) {
      res.status(500).send("DB error");
      return;
    }
    if (row) {
      // VULNERABLE: returning username directly into response (reflected XSS risk later)
      res.send(`<h1>Welcome, ${row.username}</h1>`);
    } else {
      res.send("Invalid credentials");
    }
  });
});

// 2) Reflected XSS: returns user-provided text unescaped
app.get('/greet', (req, res) => {
  const name = req.query.name || 'Guest';
  // VULNERABLE: directly embedding user input into HTML without escaping
  res.send(`<html><body><h2>Hello ${name}</h2></body></html>`);
});

// 3) Unsafe eval usage: evaluating user input (RCE-like risk)
app.get('/calc', (req, res) => {
  const expr = req.query.expr || '1+1';
  try {
    // VULNERABLE: evaluating arbitrary expression from user
    const result = eval(expr);
    res.send(`Result: ${result}`);
  } catch (e) {
    res.status(400).send("Bad expression");
  }
});

// 4) Insecure file upload: no validation of file type or filename
const upload = multer({ dest: './uploads/' }); // files saved with original filename not normalized below
app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).send("No file");
  // VULNERABLE: moving file using provided filename without checks (path traversal risk if changed)
  const unsafeTarget = `./uploads_saved/${req.file.originalname}`;
  // attempt to move (naive)
  fs.rename(req.file.path, unsafeTarget, (err) => {
    if (err) {
      return res.status(500).send("Could not save file");
    }
    res.send(`File saved as ${req.file.originalname}`);
  });
});

// 5) Hardcoded admin check & credentials (logic flaw)
app.get('/admin', (req, res) => {
  const token = req.query.token || '';
  // VULNERABLE: hard-coded token and logic
  if (token === 'hardcoded-admin-token-123') {
    res.send('Admin panel: [sensitive info]');
  } else {
    res.status(403).send('Forbidden');
  }
});

app.listen(3000, () => console.log('Vulnerable app running on http://localhost:3000'));

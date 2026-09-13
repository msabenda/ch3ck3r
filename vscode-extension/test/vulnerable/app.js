// Ch3ck3r SAST Vulnerable Test — Node.js Express
// DO NOT DEPLOY — contains deliberate security flaws

const express = require('express');
const { exec } = require('child_process');
const mysql = require('mysql');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// 🔴 CWE-798 Hardcoded secrets
const JWT_SECRET = 'secret123';
const API_KEY = 'sk-live-abcdefghijklmnopqrstuvwxyz';
const DB_PASS = 'admin123';

// 🔴 CWE-614 Insecure cookies — no Secure/HttpOnly
app.use((req, res, next) => {
    res.cookie('session', req.sessionID);
    next();
});

// 🔴 CWE-862 No auth check
app.get('/api/users/:id', (req, res) => {
    // 🔴 CWE-639 IDOR — no ownership check
    const userId = req.params.id;

    // 🔴 CWE-89 SQL Injection
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    db.query(query, (err, results) => {
        // 🔴 CWE-200 Sensitive data in response
        res.json(results.map(u => ({
            username: u.username,
            password: u.password,
            ssn: u.ssn
        })));
    });
});

// 🔴 CWE-918 SSRF
app.post('/api/proxy', (req, res) => {
    const url = req.body.url;
    fetch(url).then(r => r.text()).then(t => res.send(t));
});

// 🔴 CWE-78 Command injection
app.post('/api/exec', (req, res) => {
    exec(req.body.cmd, (err, stdout) => {
        res.send(stdout);
    });
});

// 🔴 CWE-285 No role check on admin
app.get('/api/admin/export', (req, res) => {
    // 🔴 CWE-770 Unbounded query
    db.query('SELECT * FROM users', (err, results) => {
        res.json(results);
    });
});

// 🔴 CWE-22 Path traversal
app.get('/api/files', (req, res) => {
    const fileName = req.query.file;
    res.sendFile('/var/data/' + fileName);
});

// 🔴 CWE-915 Mass assignment
app.put('/api/users/:id', (req, res) => {
    db.query('UPDATE users SET ? WHERE id = ?', [req.body, req.params.id]);
    res.json({ ok: true });
});

// 🔴 JWT with weak secret
app.post('/api/login', (req, res) => {
    const token = jwt.sign({ user: req.body.user }, JWT_SECRET);
    res.json({ token });
});

// 🔴 CWE-200 Debug error — detailed stack trace
app.use((err, req, res, next) => {
    res.status(500).send(err.stack);
});

app.listen(3000);

// Ch3ck3r SAST Vulnerable Test — TypeScript
// Deliberate security flaws for detection testing

import express, { Request, Response } from 'express';
import { Pool } from 'pg';
import axios from 'axios';
import jwt from 'jsonwebtoken';
import fs from 'fs';

const app = express();
const db = new Pool();

// 🔴 CWE-798 Hardcoded credentials
const SECRET_KEY = 'my-super-secret-key';
const DB_URL = 'postgres://admin:password123@localhost:5432/prod';

interface User {
    id: number;
    username: string;
    password: string;
    role: string;
}

// 🔴 CWE-285 Missing auth check
app.get('/api/users/:id', async (req: Request, res: Response) => {
    const userId = req.params.id;

    // 🔴 CWE-89 SQL injection via raw query
    const result = await db.query(`SELECT * FROM users WHERE id = ${userId}`);
    const user: User = result.rows[0];

    // 🔴 CWE-200 Expose sensitive fields
    res.json({
        username: user.username,
        password: user.password
    });
});

// 🔴 CWE-918 SSRF
app.post('/api/fetch', async (req: Request, res: Response) => {
    const target = req.body.url;
    const response = await axios.get(target);
    res.json(response.data);
});

// 🔴 CWE-78 Command injection
app.post('/api/run', async (req: Request, res: Response) => {
    const cmd = req.body.command;
    const { execSync } = require('child_process');
    const output = execSync(cmd);
    res.send(output.toString());
});

// 🔴 CWE-22 Path traversal
app.get('/api/read', async (req: Request, res: Response) => {
    const path = req.query.path as string;
    const content = fs.readFileSync('/data/' + path, 'utf-8');
    res.send(content);
});

// 🔴 CWE-639 IDOR — no ownership
app.delete('/api/users/:id', async (req: Request, res: Response) => {
    await db.query(`DELETE FROM users WHERE id = ${req.params.id}`);
    res.json({ deleted: true });
});

// 🔴 Weak JWT
const token = jwt.sign({ admin: true }, 'secret', { algorithm: 'HS256' });

// 🔴 CWE-770 No pagination
app.get('/api/users', async (req: Request, res: Response) => {
    const result = await db.query('SELECT * FROM users');
    res.json(result.rows);
});

app.listen(4000);

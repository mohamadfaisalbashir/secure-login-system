const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const helmet = require('helmet');
const http = require('http');
const https = require('https');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = Number(process.env.PORT || 8080);
const BODY_LIMIT = process.env.BODY_LIMIT || '10kb';
const ENABLE_HTTPS = process.env.ENABLE_HTTPS === 'true';

const attackPatterns = [
    {
        category: 'sql_injection',
        pattern: /(?:\bunion\b\s+\bselect\b|\bor\b\s+1\s*=\s*1|\bdrop\b\s+\btable\b|'\s*--|--\s)/i
    },
    {
        category: 'xss',
        pattern: /(?:<script|javascript:|on(?:error|load|click|mouseover)\s*=)/i
    }
];

// Keamanan header dasar untuk semua respons.
app.use(helmet());
app.use(cors());
app.use(express.json({
    limit: BODY_LIMIT,
    verify: (req, _res, buffer) => {
        req.rawBody = buffer.toString('utf8');
    }
}));

// Serve static frontend files
app.use(express.static(path.join(__dirname, '../frontend')));

app.get('/', (req, res) => {
    res.redirect('/login.html');
});

app.get('/health', (_req, res) => {
    res.json({
        status: 'ok',
        protocol: ENABLE_HTTPS ? 'https' : 'http'
    });
});

// Database connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const escapeHTML = (str) => {
    if (!str) return str;
    return str.replace(/[&<>'"]/g, tag => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        "'": '&#39;',
        '"': '&quot;'
    }[tag]));
};

const detectAttack = (payload = '') => {
    for (const signature of attackPatterns) {
        if (signature.pattern.test(payload)) {
            return signature.category;
        }
    }

    return null;
};

const inspectAttackPayload = (req, res, next) => {
    const rawBody = req.rawBody || '';
    const serializedBody = JSON.stringify(req.body || {});
    const combinedPayload = `${req.originalUrl}\n${serializedBody}\n${rawBody}`;
    const detectedCategory = detectAttack(combinedPayload);

    if (detectedCategory) {
        console.warn(`[SECURITY BLOCK] ${detectedCategory} dari ${req.ip}`);
        return res.status(403).json({
            error: 'Permintaan diblokir oleh proteksi aplikasi',
            category: detectedCategory
        });
    }

    if (Buffer.byteLength(rawBody, 'utf8') > 512) {
        console.warn(`[SECURITY BLOCK] payload_anomaly dari ${req.ip}`);
        return res.status(413).json({
            error: 'Payload melebihi batas aman aplikasi',
            category: 'payload_anomaly'
        });
    }

    next();
};

// Validasi Input
const validateInput = (req, res, next) => {
    let { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username dan password wajib diisi' });
    }

    if (typeof username !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ error: 'Format input tidak valid' });
    }

    if (username.length > 30 || password.length > 30) {
        return res.status(400).json({ error: 'Input terlalu panjang' });
    }

    const usernameRegex = /^[a-zA-Z0-9_]+$/;
    if (!usernameRegex.test(username)) {
        return res.status(400).json({
            error: 'Username hanya boleh berisi huruf, angka, dan underscore'
        });
    }

    req.body.username = escapeHTML(username);
    next();
};

app.use('/api', inspectAttackPayload);

// Register Endpoint
app.post('/api/register', validateInput, async (req, res) => {
    const { username, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            [username, hashedPassword]
        );

        res.status(201).json({ message: 'Registrasi berhasil' });
    } catch (error) {
        console.error('[ERROR REGISTRASI]:', error);

        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'Username sudah terdaftar' });
        }

        res.status(500).json({ error: 'Terjadi kesalahan pada server' });
    }
});

const loginLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 3,
    message: { error: 'Terlalu banyak percobaan login, IP Anda diblokir sementara selama 1 menit.' },
    standardHeaders: true,
    legacyHeaders: false
});

// Login Endpoint
app.post('/api/login', loginLimiter, validateInput, async (req, res) => {
    const { username, password } = req.body;

    try {
        const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);
        if (rows.length === 0) {
            return res.status(401).json({ error: 'Username atau password salah' });
        }

        const user = rows[0];
        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Username atau password salah' });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({ message: 'Login berhasil', token, username: user.username });
    } catch (error) {
        console.error('[ERROR LOGIN]:', error);
        res.status(500).json({ error: 'Terjadi kesalahan pada server' });
    }
});

app.use((err, _req, res, _next) => {
    if (err.type === 'entity.too.large') {
        return res.status(413).json({
            error: 'Payload melebihi batas aman aplikasi',
            category: 'payload_anomaly'
        });
    }

    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        return res.status(400).json({ error: 'Format JSON tidak valid' });
    }

    console.error('[ERROR SERVER]:', err);
    res.status(500).json({ error: 'Terjadi kesalahan pada server' });
});

const createServer = () => {
    if (!ENABLE_HTTPS) {
        return {
            server: http.createServer(app),
            protocolLabel: 'HTTP'
        };
    }

    const sslOptions = {
        key: fs.readFileSync(path.join(__dirname, 'key.pem')),
        cert: fs.readFileSync(path.join(__dirname, 'cert.pem')),
        secureOptions: crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1,
        ciphers: [
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'DHE-RSA-AES256-GCM-SHA384',
            'DHE-RSA-AES128-GCM-SHA256'
        ].join(':'),
        honorCipherOrder: true
    };

    return {
        server: https.createServer(sslOptions, app),
        protocolLabel: 'HTTPS'
    };
};

const { server, protocolLabel } = createServer();
server.listen(PORT, () => {
    console.log(`Server ${protocolLabel} berjalan di port ${PORT}`);
});

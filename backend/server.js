const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const helmet = require('helmet');
const https = require('https');
const fs = require('fs');
require('dotenv').config();

const app = express();

// 1. Keamanan Header & XSS Protection
app.use(helmet()); 
app.use(cors());

// 2. Mencegah Buffer Overflow (Batasi payload maksimal 10kb)
app.use(express.json({ limit: '10kb' })); 

// Serve static frontend files
app.use(express.static(path.join(__dirname, '../frontend')));

app.get('/', (req, res) => {
    res.redirect('/login.html');
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

// Middleware Validasi Input (Lapis Pertahanan Tambahan XSS & Buffer Overflow)
const validateInput = (req, res, next) => {
    const { username, password } = req.body;
    
    if (!username || !password) return res.status(400).json({ error: 'Username dan password wajib diisi' });
    
    // Cek panjang (Buffer Overflow / DoS layer)
    if (username.length > 50 || password.length > 100) {
        return res.status(400).json({ error: 'Input terlalu panjang' });
    }

    // Cek karakter (Mencegah karakter aneh untuk XSS/SQLi)
    const usernameRegex = /^[a-zA-Z0-9_]+$/;
    if (!usernameRegex.test(username)) {
        return res.status(400).json({ error: 'Username hanya boleh huruf, angka, dan underscore' });
    }

    next();
};

// Register Endpoint
app.post('/api/register', validateInput, async (req, res) => {
    const { username, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await pool.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            [username, hashedPassword]
        );
        res.status(201).json({ message: 'Registrasi berhasil' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            res.status(409).json({ error: 'Username sudah terdaftar' });
        } else {
            res.status(500).json({ error: 'Terjadi kesalahan pada server' });
        }
    }
});

// Login Endpoint
app.post('/api/login', validateInput, async (req, res) => {
    const { username, password } = req.body;
    try {
        const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);
        if (rows.length === 0) return res.status(401).json({ error: 'Username atau password salah' });

        const user = rows[0];
        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        if (!isValidPassword) return res.status(401).json({ error: 'Username atau password salah' });

        const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: 'Login berhasil', token, username: user.username });
    } catch (error) {
        res.status(500).json({ error: 'Terjadi kesalahan pada server' });
    }
});

// Konfigurasi HTTPS
const sslOptions = {
    key: fs.readFileSync(path.join(__dirname, 'key.pem')),
    cert: fs.readFileSync(path.join(__dirname, 'cert.pem'))
};

// Start HTTPS Server
const PORT = process.env.PORT || 8080;
https.createServer(sslOptions, app).listen(PORT, () => {
    console.log(`Server HTTPS berjalan secara aman di port ${PORT}`);
});
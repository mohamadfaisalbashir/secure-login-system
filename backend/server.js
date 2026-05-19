const express    = require('express');
const mysql      = require('mysql2/promise');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const path       = require('path');
const helmet     = require('helmet');
const http       = require('http');
const https      = require('https');
const rateLimit  = require('express-rate-limit');
const compression = require('compression');
const fs         = require('fs');
const crypto     = require('crypto');
require('dotenv').config();

const app         = express();
const PORT        = Number(process.env.PORT || 8080);
const BODY_LIMIT  = process.env.BODY_LIMIT || '10kb';
const ENABLE_HTTPS = process.env.ENABLE_HTTPS === 'true';
const IS_PROD     = process.env.NODE_ENV === 'production';

// =============================================================================
// Pola serangan untuk deteksi di application layer
// =============================================================================
const attackPatterns = [
    // Diperbarui: Lebih fleksibel menangkap variasi SQLi, termasuk string kutip dan wildcard komparasi
    { category: 'sql_injection', pattern: /(?:\bunion\b\s+\bselect\b|\bor\b\s+.*?=|\bdrop\b\s+\btable\b|'[\s]*--|--\s)/i },
    { category: 'xss',           pattern: /(?:<script|javascript:|on(?:error|load|click|mouseover)\s*=)/i }
]

// =============================================================================
// Middleware: Keamanan & Performa
// =============================================================================

// Kompresi gzip/brotli untuk semua respons (mempercepat transfer)
app.use(compression({
    level: 6,           // level 6 = sweet spot kecepatan vs ukuran
    threshold: 1024,    // hanya kompres jika > 1KB
    filter: (req, res) => {
        if (req.headers['x-no-compression']) return false;
        return compression.filter(req, res);
    }
}));

// HTTP Security Headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc:  ["'self'", "https://cdnjs.cloudflare.com"],
            styleSrc:   ["'self'", "https://cdnjs.cloudflare.com", "'unsafe-inline'"],
            fontSrc:    ["'self'", "https://cdnjs.cloudflare.com"],
            imgSrc:     ["'self'", "data:"],
            connectSrc: ["'self'"]
        }
    },
    // Paksa HTTPS selama 1 tahun
    strictTransportSecurity: ENABLE_HTTPS
        ? { maxAge: 31536000, includeSubDomains: true }
        : false,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

app.use(cors({
    origin: IS_PROD ? false : '*',   // di produksi hanya izinkan same-origin
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({
    limit: BODY_LIMIT,
    verify: (req, _res, buffer) => { req.rawBody = buffer.toString('utf8'); }
}));

// =============================================================================
// Static files dengan cache agresif (frontend jarang berubah)
// =============================================================================
const ONE_YEAR = 365 * 24 * 60 * 60 * 1000;
const ONE_HOUR = 60 * 60 * 1000;

app.use(express.static(path.join(__dirname, '../frontend'), {
    maxAge:    ONE_YEAR,      // cache asset 1 tahun (versioned via ?v=...)
    etag:      true,
    lastModified: true,
    setHeaders: (res, filePath) => {
        // HTML jangan di-cache terlalu lama agar update langsung terlihat
        if (filePath.endsWith('.html')) {
            res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');
        }
        // Font dan gambar boleh cache lama
        if (/\.(woff2?|ttf|eot|svg|jpg|jpeg|png|gif|webp|ico)$/i.test(filePath)) {
            res.setHeader('Cache-Control', `public, max-age=${ONE_YEAR / 1000}, immutable`);
        }
    }
}));

app.get('/', (_req, res) => res.redirect('/login.html'));

// Health-check endpoint (dipakai Snort setup.sh)
app.get('/health', (_req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json({ status: 'ok', protocol: ENABLE_HTTPS ? 'https' : 'http' });
});

// =============================================================================
// Database connection pool — lebih banyak koneksi, keep-alive aktif
// =============================================================================
const pool = mysql.createPool({
    host:             process.env.DB_HOST,
    user:             process.env.DB_USER,
    password:         process.env.DB_PASSWORD,
    database:         process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit:  20,           // naik dari 10 → 20
    queueLimit:       50,
    enableKeepAlive:  true,
    keepAliveInitialDelay: 10000,   // keep-alive setelah 10 detik idle
    connectTimeout:   5000,
    // Cache prepared statement agar query berulang lebih cepat
    namedPlaceholders: false
});

// Warm-up pool saat startup agar request pertama tidak lambat
pool.getConnection()
    .then(conn => { conn.release(); console.log('[DB] Connection pool siap'); })
    .catch(err  => console.error('[DB] Gagal warm-up pool:', err.message));

// =============================================================================
// Security Middleware
// =============================================================================
const detectAttack = (payload = '') => {
    for (const sig of attackPatterns) {
        if (sig.pattern.test(payload)) return sig.category;
    }
    return null;
};

const inspectAttackPayload = (req, res, next) => {
    const rawBody    = req.rawBody || '';
    const combined   = `${req.originalUrl}\n${JSON.stringify(req.body || {})}\n${rawBody}`;
    const detected   = detectAttack(combined);

    // 1. Tangani SQLi & XSS dengan peringatan spesifik
    if (detected) {
        console.warn(`[SECURITY BLOCK] ${detected} dari ${req.ip}`);
        
        let pesan = 'Aktivitas mencurigakan diblokir.';
        if (detected === 'sql_injection') {
            pesan = 'Akses ditolak: Terdeteksi upaya serangan SQL Injection!';
        } else if (detected === 'xss') {
            pesan = 'Akses ditolak: Terdeteksi upaya serangan Cross-Site Scripting (XSS)!';
        }
        return res.status(403).json({ error: pesan, category: detected });
    }

    // 2. Proteksi Buffer Overflow yang lebih andal (cek header & rawBody)
    const contentLength = parseInt(req.headers['content-length'] || '0', 10);
    if (contentLength > 1024 || Buffer.byteLength(rawBody, 'utf8') > 1024) {
        console.warn(`[SECURITY BLOCK] payload_anomaly dari ${req.ip}`);
        return res.status(413).json({ error: 'Akses ditolak: Ukuran payload melebihi batas (Indikasi Buffer Overflow)!', category: 'payload_anomaly' });
    }
    next();
};
const validateInput = (req, res, next) => {
    const { username, password } = req.body;
    if (!username || !password)
        return res.status(400).json({ error: 'Username dan password wajib diisi' });
    if (typeof username !== 'string' || typeof password !== 'string')
        return res.status(400).json({ error: 'Format input tidak valid' });
    if (username.length > 30 || password.length > 30)
        return res.status(400).json({ error: 'Input terlalu panjang' });
    if (!/^[a-zA-Z0-9_]+$/.test(username))
        return res.status(400).json({ error: 'Username hanya boleh berisi huruf, angka, dan underscore' });
    next();
};

app.use('/api', inspectAttackPayload);

// =============================================================================
// API Endpoints
// =============================================================================
app.post('/api/register', validateInput, async (req, res) => {
    const { username, password } = req.body;
    try {
        // bcrypt cost 10 sudah aman; tidak perlu dinaikkan agar tidak lambat
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            [username, hashedPassword]
        );
        res.status(201).json({ message: 'Registrasi berhasil' });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY')
            return res.status(409).json({ error: 'Username sudah terdaftar' });
        console.error('[ERROR REGISTRASI]:', err);
        res.status(500).json({ error: 'Terjadi kesalahan pada server' });
    }
});

const loginLimiter = rateLimit({
    windowMs:       60 * 1000,
    max:            3,
    message:        { error: 'Terdeteksi percobaan Brute Force! IP diblokir selama 1 menit.', category: 'brute_force' },
    standardHeaders: true,
    legacyHeaders:  false,

    keyGenerator: (req) => {
        console.log(`[RATE LIMIT] Mengevaluasi IP: ${req.ip}`);
        return req.ip; 
    },
    
    skip: (req) => req.path === '/health'
});

app.post('/api/login', loginLimiter, validateInput, async (req, res) => {
    const { username, password } = req.body;
    try {
        const [rows] = await pool.execute(
            'SELECT id, username, password_hash FROM users WHERE username = ? LIMIT 1',
            [username]
        );
        if (rows.length === 0)
            return res.status(401).json({ error: 'Username atau password salah' });

        const user = rows[0];
        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid)
            return res.status(401).json({ error: 'Username atau password salah' });

        const token = jwt.sign(
            { id: user.id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '1h', algorithm: 'HS256' }
        );
        res.json({ message: 'Login berhasil', token, username: user.username });
    } catch (err) {
        console.error('[ERROR LOGIN]:', err);
        res.status(500).json({ error: 'Terjadi kesalahan pada server' });
    }
});

// =============================================================================
// Error handler global
// =============================================================================
app.use((err, _req, res, _next) => {
    if (err.type === 'entity.too.large')
        return res.status(413).json({ error: 'Akses ditolak: Ukuran payload melebihi batas (Indikasi Buffer Overflow)!', category: 'payload_anomaly' });
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err)
        return res.status(400).json({ error: 'Format JSON tidak valid' });
    console.error('[ERROR SERVER]:', err);
    res.status(500).json({ error: 'Terjadi kesalahan pada server' });
});

// =============================================================================
// Buat server HTTP atau HTTPS
// =============================================================================
const createServer = () => {
    if (!ENABLE_HTTPS) {
        console.warn('[SERVER] Berjalan dalam mode HTTP (non-produksi)');
        return { server: http.createServer(app), label: 'HTTP' };
    }

    const certPath = path.join(__dirname, 'cert.pem');
    const keyPath  = path.join(__dirname, 'key.pem');

    if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
        console.error('[SERVER] cert.pem / key.pem tidak ditemukan! Pastikan sudah di-mount.');
        process.exit(1);
    }

    const sslOptions = {
        key:  fs.readFileSync(keyPath),
        cert: fs.readFileSync(certPath),
        // Hanya TLS 1.2 dan 1.3
        secureOptions: crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1,
        ciphers: [
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'DHE-RSA-AES256-GCM-SHA384',
            'DHE-RSA-AES128-GCM-SHA256'
        ].join(':'),
        honorCipherOrder: true,
        // HTTP/2 mempercepat multiple request secara paralel
        allowHTTP1: true
    };

    return { server: https.createServer(sslOptions, app), label: 'HTTPS' };
};

const { server, label } = createServer();

server.keepAliveTimeout    = 65000;   // lebih panjang dari load balancer default (60s)
server.headersTimeout      = 66000;
server.maxConnections      = 500;     // batasi koneksi maksimum

server.listen(PORT, () => {
    console.log(`[SERVER] ${label} berjalan di port ${PORT} (${IS_PROD ? 'production' : 'development'})`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('[SERVER] SIGTERM diterima, menutup server...');
    server.close(() => {
        pool.end();
        process.exit(0);
    });
});
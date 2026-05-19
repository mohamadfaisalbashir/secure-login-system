# 🔐 SecureAuth — Authentication System with Multi-Layer Security

> A hardened web authentication system featuring layered defenses against common attack vectors, intrusion detection/prevention, and cryptographic best practices.

---

## 📁 Project Structure

```
.
├── backend/
│   ├── Dockerfile
│   ├── init.sql
│   ├── package.json
│   ├── package-lock.json
│   └── server.js
├── frontend/
│   ├── assets/
│   │   ├── awan.jpg
│   │   ├── script.js
│   │   └── style.css
│   ├── dashboard.html
│   ├── login.html
│   └── register.html
├── snort/
│   ├── Dockerfile
│   ├── local.rules
│   └── setup.sh
├── .gitignore
└── docker-compose.yml
```

---

## 🛡️ Security Features

### 1. Password Hashing with Salt
- Every password is hashed using **bcrypt** with a unique per-user salt.
- Salting prevents rainbow table and precomputed hash attacks.
- Even identical passwords produce different hashes across users.

### 2. Anti Cross-Site Scripting (XSS)
- All user inputs are **sanitized and escaped** before being rendered in the DOM.
- HTTP response headers include:
  - `Content-Security-Policy (CSP)` to restrict script sources.
  - `X-XSS-Protection: 1; mode=block` for legacy browser support.
- Output encoding is applied to all dynamic content.

### 3. SQL Injection (SQLi) Prevention
- All database queries use **parameterized statements / prepared statements**.
- No raw string concatenation is used in SQL queries.
- Database user is granted **least-privilege** access — no DROP, ALTER, or admin rights.

### 4. Buffer Overflow Protection
- Input length is **validated and capped** on both client and server sides.
- Node.js's memory-safe runtime mitigates low-level buffer overflow risks.
- Request body size is limited using middleware (e.g., `express.json({ limit: '10kb' })`).

### 5. Brute Force Protection
- **Rate limiting** is enforced on `/login` and `/register` endpoints.
- After N consecutive failed attempts, the account is temporarily locked.
- IP-based throttling using middleware (e.g., `express-rate-limit`).
- Optional CAPTCHA integration for suspicious clients.

### 6. HTTPS with ECDSA 256-bit Certificate
- All traffic is served over **HTTPS only** — HTTP requests are redirected.
- TLS certificate uses **Elliptic Curve Digital Signature Algorithm (ECDSA) with P-256**.
- ECDSA-256 provides strong security with smaller key sizes and faster handshakes compared to RSA.
- HSTS header (`Strict-Transport-Security`) is set to enforce HTTPS for future visits.

### 7. Access Control List (ACL)
- Role-based access control (RBAC) is implemented at the route level.
- Authenticated routes are protected by JWT middleware.
- Users can only access their own resources — privilege escalation is blocked.
- Admin-only routes are separated and double-verified.

---

## 🚨 IDS & IPS — Snort Integration

This project uses **Snort** as both an Intrusion Detection System (IDS) and Intrusion Prevention System (IPS), running in a dedicated Docker container alongside the application.

### Detected & Blocked Threats

| Threat | Rule Type | Action |
|---|---|---|
| Port scanning | TCP/UDP pattern | Alert + Drop |
| ICMP Flood | ICMP threshold | Alert + Drop |
| Brute force login | HTTP rate + pattern | Alert + Drop |
| XSS payload in request | HTTP content match | Alert + Drop |
| SQL injection attempt | HTTP content match | Alert + Drop |
| Large abnormal payload | Packet size threshold | Alert + Drop |

### ICMP Flood Detection

Snort is configured with a threshold rule to detect and block ICMP flood attacks:

```
# local.rules excerpt
alert icmp any any -> $HOME_NET any (msg:"ICMP Flood Detected"; \
  threshold: type both, track by_src, count 100, seconds 5; \
  classtype:attempted-dos; sid:1000001; rev:1;)
```

Packets exceeding the defined rate are dropped at the network level when running in **inline (IPS) mode**.

### Snort Deployment

Snort runs in **inline mode** using an `afpacket` interface to sit between network traffic and the application. The `setup.sh` script handles:

1. Installing Snort and dependencies.
2. Configuring network interfaces.
3. Loading `local.rules` with custom detection signatures.
4. Starting Snort in IPS mode.

---

## 🚀 Getting Started

### Prerequisites

- [Docker](https://www.docker.com/) and [Docker Compose](https://docs.docker.com/compose/)
- Two network interfaces (for Snort inline/IPS mode) — or use bridge mode for IDS only.

### Run with Docker Compose

```bash
# Clone the repository
git clone https://github.com/mohamadfaisalbashir/secure-login-system.git
secure-login-system

# Start all services (backend, database, snort)
docker-compose up --build
```

The application will be available at: `https://localhost`

### Services

| Service | Port | Description |
|---|---|---|
| Frontend | 443 (HTTPS) | Login, Register, Dashboard |
| Backend API | 3000 | Node.js Express REST API |
| Database | 5432 | PostgreSQL |
| Snort | — | IDS/IPS (network layer) |

---

## ⚙️ Environment Variables

Create a `.env` file in the project root (see `.gitignore` — this file is excluded from version control):

```env
DB_HOST=db
DB_PORT=5432
DB_USER=secureauth_user
DB_PASSWORD=your_strong_password_here
DB_NAME=secureauth_db

JWT_SECRET=your_jwt_secret_here
JWT_EXPIRES_IN=1h

BCRYPT_ROUNDS=12

RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX=10
```

---

## 🗄️ Database Initialization

The `init.sql` file automatically sets up the schema on first run:

- Creates the `users` table with hashed password storage.
- Applies constraints and indexes.
- Sets up a dedicated DB user with minimal privileges.

---

## 🔬 Security Testing

Recommended tools to verify the security posture:

| Tool | Purpose |
|---|---|
| OWASP ZAP | XSS, SQLi, active scanning |
| Burp Suite | Manual request/response inspection |
| hping3 / nping | ICMP flood simulation |
| Hydra | Brute force simulation |
| Nikto | Web server misconfiguration scan |
| nmap | Port scan detection via Snort |
| testssl.sh | Verify ECDSA certificate and TLS config |

---

## 📜 License

This project is intended for **educational purposes**. Always follow responsible disclosure and local laws when performing security testing.

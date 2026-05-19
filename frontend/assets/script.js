const API_URL = '/api';

// Helper: fetch dengan timeout agar tidak nunggu selamanya
async function fetchWithTimeout(url, options = {}, timeoutMs = 8000) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeoutMs);
    try {
        return await fetch(url, { ...options, signal: controller.signal });
    } finally {
        clearTimeout(id);
    }
}

// 1. Login
const loginForm = document.getElementById('login-form');
if (loginForm) {
    if (localStorage.getItem('token')) {
        window.location.replace('dashboard.html');
    }

    loginForm.addEventListener('submit', async function (e) {
        e.preventDefault();
        const btn      = loginForm.querySelector('button[type=submit]');
        const username = document.getElementById('login-username').value.trim();
        const password = document.getElementById('login-password').value;

        btn.disabled    = true;
        btn.textContent = 'Memproses...';

        try {
            const res  = await fetchWithTimeout(`${API_URL}/login`, {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify({ username, password })
            });
            const data = await res.json();

            if (res.ok) {
                localStorage.setItem('token',         data.token);
                localStorage.setItem('savedUsername', data.username);
                window.location.replace('dashboard.html');
            } else {
                alert(data.error || 'Login gagal');
                btn.disabled    = false;
                btn.textContent = 'Mulai Masuk';
            }
        } catch (err) {
            alert(err.name === 'AbortError'
                ? 'Koneksi timeout. Coba lagi.'
                : 'Akses ditolak: Request diputus oleh IPS/Snort karena terdeteksi aktivitas berbahaya.');
            btn.disabled    = false;
            btn.textContent = 'Mulai Masuk';
        }
    });
}

// 2. Register
const registerForm = document.getElementById('register-form');
if (registerForm) {
    registerForm.addEventListener('submit', async function (e) {
        e.preventDefault();
        const btn      = registerForm.querySelector('button[type=submit]');
        const username = document.getElementById('reg-username').value.trim();
        const password = document.getElementById('reg-password').value;

        btn.disabled    = true;
        btn.textContent = 'Mendaftarkan...';

        try {
            const res  = await fetchWithTimeout(`${API_URL}/register`, {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify({ username, password })
            });
            const data = await res.json();

            if (res.ok) {
                alert('Registrasi berhasil! Silakan login.');
                window.location.replace('login.html');
            } else {
                alert(data.error || 'Registrasi gagal');
                btn.disabled    = false;
                btn.textContent = 'Daftar Sekarang';
            }
        } catch (err) {
            alert(err.name === 'AbortError'
                ? 'Koneksi timeout. Coba lagi.'
                : 'Akses ditolak: Request diputus oleh IPS/Snort karena terdeteksi aktivitas berbahaya.');
            btn.disabled    = false;
            btn.textContent = 'Daftar Sekarang';
        }
    });
}

// 3. Dashboard
const welcomeMessage = document.getElementById('welcome-message');
if (welcomeMessage) {
    const token = localStorage.getItem('token');
    if (!token) {
        window.location.replace('login.html');
    } else {
        const storedName = localStorage.getItem('savedUsername') || 'User';
        welcomeMessage.textContent = `Halo, ${storedName}!`;
    }
}

// 4. Logout
const btnLogout = document.getElementById('btn-logout');
if (btnLogout) {
    btnLogout.addEventListener('click', function () {
        localStorage.removeItem('token');
        localStorage.removeItem('savedUsername');
        window.location.replace('login.html');
    });
}


// 5. Toggle Password Visibility
function setupPasswordToggle(toggleId, inputId) {
    const icon  = document.getElementById(toggleId);
    const input = document.getElementById(inputId);
    if (!icon || !input) return;

    icon.addEventListener('click', function () {
        const isPassword = input.type === 'password';
        input.type       = isPassword ? 'text' : 'password';
        icon.classList.toggle('fa-eye-slash', !isPassword);
        icon.classList.toggle('fa-eye',        isPassword);
        icon.style.color = isPassword ? '#00ffff' : '#94a3b8';
    });
}

setupPasswordToggle('toggle-login-password', 'login-password');
setupPasswordToggle('toggle-reg-password',   'reg-password');
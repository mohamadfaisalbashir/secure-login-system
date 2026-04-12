const API_URL = '/api';

// 1. Logika untuk Halaman Login
const loginForm = document.getElementById('login-form');
if (loginForm) {
    loginForm.addEventListener('submit', async function(e) {
        e.preventDefault(); 
        const usernameInput = document.getElementById('login-username').value;
        const passwordInput = document.getElementById('login-password').value;
        
        try {
            const response = await fetch(`${API_URL}/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: usernameInput, password: passwordInput })
            });
            const data = await response.json();

            if (response.ok) {
                localStorage.setItem('token', data.token);
                localStorage.setItem('savedUsername', data.username);
                window.location.href = 'dashboard.html';
            } else {
                alert(data.error || 'Login gagal');
            }
        } catch (error) {
            alert('Kesalahan koneksi jaringan.');
        }
    });
}

// 2. Logika untuk Halaman Register
const registerForm = document.getElementById('register-form');
if (registerForm) {
    registerForm.addEventListener('submit', async function(e) {
        e.preventDefault(); 
        const usernameInput = document.getElementById('reg-username').value;
        const passwordInput = document.getElementById('reg-password').value;
        
        try {
            const response = await fetch(`${API_URL}/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: usernameInput, password: passwordInput })
            });
            const data = await response.json();

            if (response.ok) {
                alert('Registrasi berhasil! Silakan login.');
                window.location.href = 'login.html';
            } else {
                alert(data.error || 'Registrasi gagal');
            }
        } catch (error) {
            alert('Kesalahan koneksi jaringan.');
        }
    });
}

// 3. Logika untuk Halaman Dashboard
const welcomeMessage = document.getElementById('welcome-message');
if (welcomeMessage) {
    const token = localStorage.getItem('token');
    if (!token) {
        // Redirect jika belum login
        window.location.href = 'login.html';
    } else {
        const storedName = localStorage.getItem('savedUsername') || 'User';
        welcomeMessage.textContent = `Halo, ${storedName}!`;
    }
}

// 4. Fungsi Logout
function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('savedUsername');
    window.location.href = 'login.html';
}

// 5. Logika untuk Toggle Show/Hide Password
function setupPasswordToggle(toggleIconId, passwordInputId) {
    const toggleIcon = document.getElementById(toggleIconId);
    const passwordInput = document.getElementById(passwordInputId);

    if (toggleIcon && passwordInput) {
        toggleIcon.addEventListener('click', function () {
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);
            this.classList.toggle('fa-eye-slash');
            this.classList.toggle('fa-eye');
            if (type === 'text') {
                this.style.color = '#00ffff';
            } else {
                this.style.color = '#94a3b8';
            }
        });
    }
}

setupPasswordToggle('toggle-login-password', 'login-password');
setupPasswordToggle('toggle-reg-password', 'reg-password');
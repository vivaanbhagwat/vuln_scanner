/**
 * CyberShield - Frontend JavaScript
 * Auto Website Vulnerability Scanner
 */

// --- Password Toggle ---
function togglePassword(fieldId) {
    const field = document.getElementById(fieldId);
    const eye = document.getElementById(fieldId + '-eye');
    if (field.type === 'password') {
        field.type = 'text';
        eye.classList.replace('bi-eye', 'bi-eye-slash');
    } else {
        field.type = 'password';
        eye.classList.replace('bi-eye-slash', 'bi-eye');
    }
}

// --- Password Strength Indicator ---
document.addEventListener('DOMContentLoaded', function() {
    const pwField = document.getElementById('password');
    const strengthBar = document.getElementById('passwordStrength');

    if (pwField && strengthBar) {
        pwField.addEventListener('input', function() {
            const pw = this.value;
            let score = 0;

            if (pw.length >= 8) score++;
            if (pw.length >= 12) score++;
            if (/[a-z]/.test(pw)) score++;
            if (/[A-Z]/.test(pw)) score++;
            if (/\d/.test(pw)) score++;
            if (/[@$!%*?&#^()_\-+=]/.test(pw)) score++;

            const percent = Math.min((score / 6) * 100, 100);
            let color = '#e74c3c';
            let label = 'Weak';

            if (score >= 5) { color = '#2ecc71'; label = 'Strong'; }
            else if (score >= 3) { color = '#f39c12'; label = 'Medium'; }

            strengthBar.innerHTML = `
                <div class="bar" style="width:${percent}%;background:${color};"></div>
            `;
            strengthBar.title = label;
        });
    }

    // --- Auto-dismiss flash alerts ---
    const alerts = document.querySelectorAll('.glass-alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.classList.remove('show');
            setTimeout(() => alert.remove(), 300);
        }, 5000);
    });

    // --- Animate numbers (stat cards) ---
    const statNumbers = document.querySelectorAll('.stat-card h2');
    statNumbers.forEach(el => {
        const target = parseInt(el.textContent);
        if (isNaN(target) || target === 0) return;
        
        let current = 0;
        const step = Math.max(1, Math.floor(target / 30));
        const timer = setInterval(() => {
            current += step;
            if (current >= target) {
                current = target;
                clearInterval(timer);
            }
            el.textContent = current;
        }, 30);
    });

    // --- Risk circle fill animation ---
    const riskCircles = document.querySelectorAll('.risk-circle');
    riskCircles.forEach(circle => {
        const scoreEl = circle.querySelector('.risk-score-value');
        if (!scoreEl) return;
        const score = parseInt(scoreEl.textContent);
        const deg = (score / 100) * 360;
        
        let color = '#2ecc71';
        if (score >= 70) color = '#e74c3c';
        else if (score >= 40) color = '#f39c12';

        setTimeout(() => {
            circle.style.background = `conic-gradient(${color} ${deg}deg, rgba(255,255,255,0.05) ${deg}deg)`;
        }, 300);
    });
});

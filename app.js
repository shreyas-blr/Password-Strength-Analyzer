/* =============================================
   Password Strength Analyzer — Application Logic
   Mirrors source_code.py logic in the browser
   ============================================== */

// --- Common weak passwords & words (from source_code.py) ---
const COMMON_PASSWORDS = new Set([
    "123456", "password", "123456789", "qwerty", "abc123",
    "password123", "admin", "letmein", "welcome"
]);

const COMMON_WORDS = new Set(["hello", "india", "user", "login", "test"]);

// --- Entropy Calculation (mirrors source_code.py) ---
function calculateEntropy(password) {
    let pool = 0;
    if (/[a-z]/.test(password)) pool += 26;
    if (/[A-Z]/.test(password)) pool += 26;
    if (/[0-9]/.test(password)) pool += 10;
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) pool += 32;
    if (pool === 0) return 0;
    return password.length * Math.log2(pool);
}

// --- Pattern Check (mirrors source_code.py) ---
function checkPatterns(password) {
    const issues = [];
    if (/(.)\1{2,}/.test(password)) {
        issues.push("Avoid repeated characters (e.g., aaa)");
    }
    const sequences = ["123", "abc", "qwerty", "password"];
    for (const seq of sequences) {
        if (password.toLowerCase().includes(seq)) {
            issues.push(`Avoid predictable sequence: ${seq}`);
        }
    }
    return issues;
}

// --- Main Strength Check (mirrors source_code.py) ---
function checkPasswordStrength(password) {
    let score = 0;
    const feedback = [];

    // Common password
    if (COMMON_PASSWORDS.has(password.toLowerCase())) {
        return { strength: "Very Weak", entropy: 0, feedback: ["Common password detected"] };
    }

    // Dictionary words
    for (const word of COMMON_WORDS) {
        if (password.toLowerCase().includes(word)) {
            feedback.push("Avoid using common words");
            break;
        }
    }

    // Length scoring
    const length = password.length;
    if (length >= 12) score += 2;
    else if (length >= 8) score += 1;
    else feedback.push("Use at least 8 characters");

    // Character diversity
    if (/[A-Z]/.test(password)) score += 1;
    else feedback.push("Add uppercase letters");

    if (/[a-z]/.test(password)) score += 1;
    else feedback.push("Add lowercase letters");

    if (/[0-9]/.test(password)) score += 1;
    else feedback.push("Include numbers");

    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score += 1;
    else feedback.push("Include special characters");

    // Patterns
    const patternIssues = checkPatterns(password);
    if (patternIssues.length) {
        feedback.push(...patternIssues);
        score -= 1;
    }

    // Entropy
    const entropy = calculateEntropy(password);

    // Strength classification (same thresholds as source_code.py)
    let strength;
    if (entropy < 28) strength = "Very Weak";
    else if (entropy < 36) strength = "Weak";
    else if (entropy < 60) strength = "Medium";
    else if (entropy < 80) strength = "Strong";
    else strength = "Very Strong";

    return { strength, entropy, feedback };
}

// --- Crack time estimation ---
function estimateCrackTime(entropy) {
    if (entropy === 0) return "Instant";
    // Assume 10 billion guesses per second
    const guessesPerSec = 1e10;
    const totalGuesses = Math.pow(2, entropy);
    const seconds = totalGuesses / guessesPerSec;

    if (seconds < 1) return "< 1 second";
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
    if (seconds < 86400 * 365) return `${Math.round(seconds / 86400)} days`;
    if (seconds < 86400 * 365 * 1000) return `${Math.round(seconds / (86400 * 365))} years`;
    if (seconds < 86400 * 365 * 1e6) return `${(seconds / (86400 * 365 * 1000)).toFixed(0)}K years`;
    if (seconds < 86400 * 365 * 1e9) return `${(seconds / (86400 * 365 * 1e6)).toFixed(0)}M years`;
    return "Centuries+";
}

// --- Character counts ---
function countCharTypes(password) {
    let lower = 0, upper = 0, digit = 0, special = 0;
    for (const ch of password) {
        if (/[a-z]/.test(ch)) lower++;
        else if (/[A-Z]/.test(ch)) upper++;
        else if (/[0-9]/.test(ch)) digit++;
        else special++;
    }
    return { lower, upper, digit, special };
}

// --- Password Generator ---
function generatePassword(length = 16) {
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const digits = '0123456789';
    const specials = '!@#$%^&*(),.?":{}|<>';
    const all = lower + upper + digits + specials;

    // Guarantee at least one of each type
    let pw = '';
    pw += lower[Math.floor(Math.random() * lower.length)];
    pw += upper[Math.floor(Math.random() * upper.length)];
    pw += digits[Math.floor(Math.random() * digits.length)];
    pw += specials[Math.floor(Math.random() * specials.length)];

    for (let i = 4; i < length; i++) {
        pw += all[Math.floor(Math.random() * all.length)];
    }

    // Shuffle
    return pw.split('').sort(() => Math.random() - 0.5).join('');
}

// --- Strength colour mapping ---
function strengthColor(strength) {
    const map = {
        "Very Weak": "var(--color-very-weak)",
        "Weak": "var(--color-weak)",
        "Medium": "var(--color-medium)",
        "Strong": "var(--color-strong)",
        "Very Strong": "var(--color-very-strong)"
    };
    return map[strength] || "var(--text-muted)";
}

function strengthLevel(strength) {
    const map = { "Very Weak": 1, "Weak": 2, "Medium": 3, "Strong": 4, "Very Strong": 5 };
    return map[strength] || 0;
}

// ===== DOM Elements =====
const passwordInput = document.getElementById('passwordInput');
const analyzeBtn = document.getElementById('analyzeBtn');
const generateBtn = document.getElementById('generateBtn');
const toggleVisibility = document.getElementById('toggleVisibility');
const themeToggle = document.getElementById('themeToggle');

const ringProgress = document.getElementById('ringProgress');
const ringScore = document.getElementById('ringScore');
const strengthLabel = document.getElementById('strengthLabel');
const bars = [
    document.getElementById('bar1'),
    document.getElementById('bar2'),
    document.getElementById('bar3'),
    document.getElementById('bar4'),
    document.getElementById('bar5')
];

const countLower = document.getElementById('countLower');
const countUpper = document.getElementById('countUpper');
const countDigit = document.getElementById('countDigit');
const countSpecial = document.getElementById('countSpecial');
const bkItems = {
    lower: document.getElementById('bkLower'),
    upper: document.getElementById('bkUpper'),
    digit: document.getElementById('bkDigit'),
    special: document.getElementById('bkSpecial')
};
const lengthBarFill = document.getElementById('lengthBarFill');
const lengthValue = document.getElementById('lengthValue');

const feedbackList = document.getElementById('feedbackList');
const crackTime = document.getElementById('crackTime');
const historyList = document.getElementById('historyList');
const clearHistory = document.getElementById('clearHistory');

const CIRCUMFERENCE = 2 * Math.PI * 52; // ring radius 52

let analysisHistory = [];

// ===== Theme Toggle =====
function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('psc-theme', theme);
}

themeToggle.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme');
    setTheme(current === 'dark' ? 'light' : 'dark');
});

// Restore saved theme
const savedTheme = localStorage.getItem('psc-theme');
if (savedTheme) setTheme(savedTheme);

// ===== Toggle Password Visibility =====
toggleVisibility.addEventListener('click', () => {
    const isPassword = passwordInput.type === 'password';
    passwordInput.type = isPassword ? 'text' : 'password';
    toggleVisibility.querySelector('.eye-open').style.display = isPassword ? 'none' : 'block';
    toggleVisibility.querySelector('.eye-closed').style.display = isPassword ? 'block' : 'none';
});

// ===== Real-time Analysis =====
passwordInput.addEventListener('input', () => {
    const pw = passwordInput.value;
    if (pw.length === 0) {
        resetUI();
        return;
    }
    runAnalysis(pw, false); // live but don't add to history
});

// ===== Analyze Button =====
analyzeBtn.addEventListener('click', () => {
    const pw = passwordInput.value.trim();
    if (!pw) {
        passwordInput.focus();
        return;
    }
    runAnalysis(pw, true);
});

// ===== Generate Password =====
generateBtn.addEventListener('click', () => {
    const pw = generatePassword(16);
    passwordInput.value = pw;
    passwordInput.type = 'text';
    toggleVisibility.querySelector('.eye-open').style.display = 'none';
    toggleVisibility.querySelector('.eye-closed').style.display = 'block';
    runAnalysis(pw, true);
});

// ===== Clear History =====
clearHistory.addEventListener('click', () => {
    analysisHistory = [];
    renderHistory();
});

// ===== Enter key =====
passwordInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') analyzeBtn.click();
});

// ===== Core Analysis Routine =====
function runAnalysis(password, addToHistory) {
    const { strength, entropy, feedback } = checkPasswordStrength(password);
    const counts = countCharTypes(password);

    // Update ring
    const maxEntropy = 120;
    const pct = Math.min(entropy / maxEntropy, 1);
    const offset = CIRCUMFERENCE * (1 - pct);
    ringProgress.style.strokeDashoffset = offset;
    ringProgress.style.stroke = strengthColor(strength);
    ringScore.textContent = Math.round(entropy);

    // Strength label
    strengthLabel.textContent = strength;
    strengthLabel.style.color = strengthColor(strength);

    // Bars
    const level = strengthLevel(strength);
    bars.forEach((bar, i) => {
        if (i < level) {
            bar.style.background = strengthColor(strength);
            bar.classList.add('active');
        } else {
            bar.style.background = '';
            bar.classList.remove('active');
        }
    });

    // Breakdown
    countLower.textContent = counts.lower;
    countUpper.textContent = counts.upper;
    countDigit.textContent = counts.digit;
    countSpecial.textContent = counts.special;

    bkItems.lower.classList.toggle('has-chars', counts.lower > 0);
    bkItems.upper.classList.toggle('has-chars', counts.upper > 0);
    bkItems.digit.classList.toggle('has-chars', counts.digit > 0);
    bkItems.special.classList.toggle('has-chars', counts.special > 0);

    // Length
    const len = password.length;
    lengthValue.textContent = len;
    lengthBarFill.style.width = Math.min(len / 24 * 100, 100) + '%';

    // Feedback
    if (feedback.length === 0) {
        feedbackList.innerHTML = `
            <div class="feedback-item success">
                <span class="feedback-icon">✓</span>
                <span>Excellent password. No suggestions needed!</span>
            </div>`;
    } else {
        feedbackList.innerHTML = feedback.map((msg, i) => `
            <div class="feedback-item warning" style="animation-delay:${i * 0.05}s">
                <span class="feedback-icon">⚠</span>
                <span>${msg}</span>
            </div>
        `).join('');
    }

    // Crack time
    const ct = estimateCrackTime(entropy);
    crackTime.textContent = ct;
    crackTime.style.color = strengthColor(strength);

    // History
    if (addToHistory) {
        const masked = password.charAt(0) + '•'.repeat(Math.max(password.length - 2, 0)) + (password.length > 1 ? password.charAt(password.length - 1) : '');
        analysisHistory.unshift({ masked, strength, entropy: Math.round(entropy) });
        if (analysisHistory.length > 10) analysisHistory.pop();
        renderHistory();
    }
}

function resetUI() {
    ringProgress.style.strokeDashoffset = CIRCUMFERENCE;
    ringProgress.style.stroke = 'var(--accent-1)';
    ringScore.textContent = '—';
    strengthLabel.textContent = 'Enter a password';
    strengthLabel.style.color = '';

    bars.forEach(b => { b.style.background = ''; b.classList.remove('active'); });

    countLower.textContent = '0';
    countUpper.textContent = '0';
    countDigit.textContent = '0';
    countSpecial.textContent = '0';
    Object.values(bkItems).forEach(el => el.classList.remove('has-chars'));

    lengthValue.textContent = '0';
    lengthBarFill.style.width = '0%';

    feedbackList.innerHTML = `
        <div class="feedback-empty">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" opacity="0.3">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            <p>Enter a password to receive suggestions</p>
        </div>`;

    crackTime.textContent = '—';
    crackTime.style.color = '';
}

function renderHistory() {
    if (analysisHistory.length === 0) {
        historyList.innerHTML = '<div class="feedback-empty"><p>No passwords analyzed yet</p></div>';
        return;
    }
    historyList.innerHTML = analysisHistory.map((h, i) => `
        <div class="history-entry" style="animation-delay:${i * 0.04}s">
            <span class="history-password">${escapeHTML(h.masked)}</span>
            <span class="history-strength" style="background:${strengthColor(h.strength)}22;color:${strengthColor(h.strength)}">${h.strength}</span>
            <span class="history-entropy">${h.entropy} bits</span>
        </div>
    `).join('');
}

function escapeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ===== Background Particles =====
function createParticles() {
    const container = document.getElementById('bgParticles');
    const count = 20;
    for (let i = 0; i < count; i++) {
        const p = document.createElement('div');
        p.className = 'particle';
        const size = Math.random() * 6 + 2;
        p.style.width = size + 'px';
        p.style.height = size + 'px';
        p.style.left = Math.random() * 100 + '%';
        p.style.animationDuration = (Math.random() * 15 + 10) + 's';
        p.style.animationDelay = (Math.random() * 10) + 's';
        container.appendChild(p);
    }
}

createParticles();

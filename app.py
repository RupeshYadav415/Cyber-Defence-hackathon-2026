

from flask import Flask, request, jsonify, render_template_string
import re
from urllib.parse import urlparse

app = Flask(__name__)


URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st"
]


COMMONLY_SPOOFED_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "bankofamerica", "wellsfargo", "instagram", "linkedin"
]


SUSPICIOUS_PHRASES = [
    "urgent action required",
    "verify your account",
    "account will be suspended",
    "account has been suspended",
    "click here immediately",
    "confirm your password",
    "confirm your identity",
    "unusual activity detected",
    "your account will be locked",
    "limited time offer",
    "act now",
    "you have won",
    "claim your prize",
    "update your billing",
    "security alert",
    "login attempt detected",
    "suspended due to",
    "failure to comply",
    "this is your final notice",
    "provide your password",
    "warning for you",
]


def looks_like_url(text: str) -> bool:
    """Heuristic: does the submitted text look like a single URL?"""
    text = text.strip()
    if " " in text or "\n" in text:
        # Multi-word / multi-line input is treated as message text
        return False
    return bool(re.match(r"^(https?://|www\.)", text, re.IGNORECASE))


def analyze_url(raw_url: str):
    """
    Runs a set of rule-based checks against a URL and returns
    a list of (flag_description, severity_points) tuples.
    """
    flags = []

    # Ensure URL has a scheme so urlparse works correctly
    url = raw_url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    # Strip port if present, e.g. example.com:8080
    domain_no_port = domain.split(":")[0]

    # --- Check 1: Not using HTTPS ---
    if parsed.scheme != "https":
        flags.append(("Connection is not secure (no HTTPS encryption)", 1))

    # --- Check 2: Domain is a raw IP address instead of a name ---
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ip_pattern, domain_no_port):
        flags.append(("URL uses a raw IP address instead of a domain name", 2))

    # --- Check 3: Known URL shortener (hides real destination) ---
    if any(shortener in domain_no_port for shortener in URL_SHORTENERS):
        flags.append(("URL uses a link-shortening service, hiding the real destination", 1))

    # --- Check 4: Excessive subdomains (e.g. login.secure.paypal.fake.com) ---
    subdomain_count = domain_no_port.count(".")
    if subdomain_count >= 3:
        flags.append(("URL has an unusually high number of subdomains", 1))

    # --- Check 5: Look-alike brand domain check ---
    for brand in COMMONLY_SPOOFED_BRANDS:
        if brand in domain_no_port:
            # If the brand name appears but the domain isn't the official one,
            # flag it as a possible look-alike (very simplified check)
            official_guess = f"{brand}.com"
            if domain_no_port != official_guess and not domain_no_port.endswith("." + official_guess):
                flags.append((f"Domain contains brand name '{brand}' but does not match its official domain", 2))
            break

    # --- Check 6: Suspicious characters / hyphens used to mimic brands ---
    if domain_no_port.count("-") >= 2:
        flags.append(("Domain uses multiple hyphens, a common phishing trick", 1))

    # --- Check 7: Misspelling-style character substitution (e.g. paypa1, 0utlook) ---
    if re.search(r"[0-9]", domain_no_port.split(".")[0]):
        flags.append(("Domain name contains numbers substituted for letters", 1))

    return flags


def analyze_text(message: str):
    """
    Scans free text (email/SMS/message) for common phishing language
    patterns and returns a list of (flag_description, severity_points).
    """
    flags = []
    lowered = message.lower()

    for phrase in SUSPICIOUS_PHRASES:
        if phrase in lowered:
            flags.append((f"Message contains manipulative phrase: \"{phrase}\"", 1))

    # Also run any URLs found inside the message text through the URL checker
    urls_found = re.findall(r"(https?://\S+|www\.\S+)", message)
    for url in urls_found:
        url_flags = analyze_url(url)
        for desc, points in url_flags:
            flags.append((f"[Link in message: {url}] {desc}", points))

    # Excessive exclamation marks / all-caps shouting is another common signal
    if message.count("!") >= 3:
        flags.append(("Message uses excessive exclamation marks", 1))

    caps_words = re.findall(r"\b[A-Z]{4,}\b", message)
    if len(caps_words) >= 2:
        flags.append(("Message uses excessive capital letters (shouting)", 1))

    return flags


def score_to_verdict(score: int):
    """Converts a numeric flag score into a Safe / Suspicious / Dangerous verdict."""
    if score == 0:
        return "Safe", "green"
    elif score <= 2:
        return "Suspicious", "orange"
    else:
        return "Dangerous", "red"


EDUCATIONAL_TIPS = [
    "Always check the sender's actual email address, not just the display name.",
    "Hover over a link before clicking to see where it really leads.",
    "Legitimate companies rarely ask you to 'verify your account' by clicking a link.",
    "If a message creates urgency or panic, slow down — that's a common phishing tactic.",
    "Type a company's website address directly into your browser instead of clicking links.",
    "Check for spelling mistakes in domain names — phishers often use look-alike spellings.",
]

import random


#Route decleration
@app.route("/")
def home():
    return render_template_string(HTML_PAGE)


@app.route("/check", methods=["POST"])
def check():
    data = request.get_json(force=True)
    user_input = (data.get("input") or "").strip()

    if not user_input:
        return jsonify({"error": "Please paste a URL or message to check."}), 400

    if looks_like_url(user_input):
        input_type = "URL"
        flags = analyze_url(user_input)
    else:
        input_type = "Email/Message Text"
        flags = analyze_text(user_input)

    score = sum(points for _, points in flags)
    verdict, color = score_to_verdict(score)
    reasons = [desc for desc, _ in flags]
    tip = random.choice(EDUCATIONAL_TIPS)

    return jsonify({
        "input_type": input_type,
        "verdict": verdict,
        "color": color,
        "score": score,
        "reasons": reasons,
        "tip": tip
    })


# for frontend 

HTML_PAGE = """""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhishGuard - Phishing Risk Checker</title>
<style>
    * { box-sizing: border-box; }
    body {
        font-family: 'Segoe UI', Arial, sans-serif;
        background: #0f1117;
        color: #e6e6e6;
        margin: 0;
        padding: 0;
        display: flex;
        justify-content: center;
        min-height: 100vh;
    }
    .container {
        max-width: 700px;
        width: 100%;
        padding: 40px 20px;
    }
    h1 {
        text-align: center;
        margin-bottom: 4px;
        color: #4fd1c5;
    }
    p.subtitle {
        text-align: center;
        color: #9aa0a6;
        margin-top: 0;
        margin-bottom: 30px;
    }
    textarea {
        width: 100%;
        min-height: 120px;
        padding: 14px;
        border-radius: 10px;
        border: 1px solid #2a2e37;
        background: #1a1d24;
        color: #e6e6e6;
        font-size: 15px;
        resize: vertical;
    }
    button {
        margin-top: 14px;
        width: 100%;
        padding: 14px;
        font-size: 16px;
        font-weight: bold;
        border: none;
        border-radius: 10px;
        background: #4fd1c5;
        color: #0f1117;
        cursor: pointer;
        transition: opacity 0.2s;
    }
    button:hover { opacity: 0.85; }
    button:disabled { opacity: 0.5; cursor: not-allowed; }

    #result {
        margin-top: 30px;
        display: none;
    }
    .verdict-card {
        border-radius: 12px;
        padding: 20px;
        border: 1px solid #2a2e37;
        background: #1a1d24;
    }
    .verdict-title {
        font-size: 22px;
        font-weight: bold;
        margin: 0 0 6px 0;
    }
    .verdict-green { color: #4ade80; }
    .verdict-orange { color: #facc15; }
    .verdict-red { color: #f87171; }

    .meta {
        color: #9aa0a6;
        font-size: 14px;
        margin-bottom: 14px;
    }
    ul.reasons {
        margin: 0;
        padding-left: 20px;
    }
    ul.reasons li {
        margin-bottom: 6px;
        font-size: 14px;
        color: #d1d5db;
    }
    .no-flags {
        color: #4ade80;
        font-size: 14px;
    }
    .tip-box {
        margin-top: 18px;
        padding: 12px 14px;
        border-radius: 8px;
        background: #14202a;
        border-left: 4px solid #4fd1c5;
        font-size: 13px;
        color: #b9c2cc;
    }
    .error-box {
        margin-top: 20px;
        color: #f87171;
        font-size: 14px;
        text-align: center;
    }

    /* --- History section --- */
    .history-section {
        margin-top: 40px;
    }
    .history-title {
        font-size: 18px;
        font-weight: bold;
        color: #9aa0a6;
        margin-bottom: 10px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .clear-history-btn {
        background: none;
        border: 1px solid #2a2e37;
        color: #9aa0a6;
        font-size: 12px;
        font-weight: normal;
        padding: 6px 12px;
        width: auto;
        margin-top: 0;
        border-radius: 6px;
    }
    .clear-history-btn:hover { opacity: 1; border-color: #4fd1c5; color: #4fd1c5; }

    .history-list {
        max-height: 280px;
        overflow-y: auto;
        border: 1px solid #2a2e37;
        border-radius: 10px;
        background: #15171e;
    }
    .history-item {
        padding: 12px 14px;
        border-bottom: 1px solid #2a2e37;
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 10px;
    }
    .history-item:last-child { border-bottom: none; }
    .history-left {
        overflow: hidden;
    }
    .history-input {
        font-size: 13px;
        color: #d1d5db;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        max-width: 420px;
    }
    .history-time {
        font-size: 11px;
        color: #6b7280;
        margin-top: 2px;
    }
    .history-badge {
        flex-shrink: 0;
        font-size: 11px;
        font-weight: bold;
        padding: 4px 10px;
        border-radius: 20px;
        white-space: nowrap;
    }
    .badge-green { background: rgba(74, 222, 128, 0.15); color: #4ade80; }
    .badge-orange { background: rgba(250, 204, 21, 0.15); color: #facc15; }
    .badge-red { background: rgba(248, 113, 113, 0.15); color: #f87171; }

    .empty-history {
        padding: 20px;
        text-align: center;
        color: #6b7280;
        font-size: 13px;
    }

    /* Scrollbar styling for history list */
    .history-list::-webkit-scrollbar { width: 8px; }
    .history-list::-webkit-scrollbar-track { background: transparent; }
    .history-list::-webkit-scrollbar-thumb { background: #2a2e37; border-radius: 10px; }
</style>
</head>
<body>
<div class="container">
    <h1>PhishGuard</h1>
    <p class="subtitle">Paste a URL or a suspicious email/message below to check its risk level</p>
    <p class="subtitle">Powered By Learnel Panel</p>

    <textarea id="userInput" placeholder="e.g. https://paypa1-secure-login.com  OR  'Your account will be suspended, click here immediately to verify!'"></textarea>
    <button id="checkBtn" onclick="checkInput()">Check Risk</button>

    <div id="result"></div>
    <div id="errorBox" class="error-box"></div>

    <div class="history-section">
        <div class="history-title">
            <span>Scan History</span>
            <button class="clear-history-btn" onclick="clearHistory()">Clear</button>
        </div>
        <div class="history-list" id="historyList">
            <div class="empty-history" id="emptyHistory">No scans yet — your checks will appear here.</div>
        </div>
    </div>
</div>

<script>
async function checkInput() {
    const input = document.getElementById('userInput').value.trim();
    const resultDiv = document.getElementById('result');
    const errorBox = document.getElementById('errorBox');
    const btn = document.getElementById('checkBtn');

    errorBox.textContent = '';
    resultDiv.style.display = 'none';

    if (!input) {
        errorBox.textContent = 'Please paste a URL or message first.';
        return;
    }

    btn.disabled = true;
    btn.textContent = 'Checking...';

    try {
        const res = await fetch('/check', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ input: input })
        });
        const data = await res.json();

        if (!res.ok) {
            errorBox.textContent = data.error || 'Something went wrong.';
            return;
        }

        renderResult(data);
        addToHistory(input, data);
    } catch (err) {
        errorBox.textContent = 'Could not reach the server. Is app.py running?';
    } finally {
        btn.disabled = false;
        btn.textContent = 'Check Risk';
    }
}

function renderResult(data) {
    const resultDiv = document.getElementById('result');

    let reasonsHtml = '';
    if (data.reasons.length === 0) {
        reasonsHtml = '<p class="no-flags">No red flags detected.</p>';
    } else {
        reasonsHtml = '<ul class="reasons">' +
            data.reasons.map(r => `<li>&#9888; ${escapeHtml(r)}</li>`).join('') +
            '</ul>';
    }

    resultDiv.innerHTML = `
        <div class="verdict-card">
            <div class="verdict-title verdict-${data.color}">${data.verdict}</div>
            <div class="meta">Input type: ${data.input_type} &middot; Risk score: ${data.score}</div>
            ${reasonsHtml}
            <div class="tip-box">&#128161; Tip: ${escapeHtml(data.tip)}</div>
        </div>
    `;
    resultDiv.style.display = 'block';
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ---------------- Scan History ----------------
let scanHistory = [];
const MAX_HISTORY_ITEMS = 20;

function addToHistory(inputText, data) {
    const entry = {
        input: inputText,
        verdict: data.verdict,
        color: data.color,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };
    scanHistory.unshift(entry); // newest first
    if (scanHistory.length > MAX_HISTORY_ITEMS) {
        scanHistory.pop();
    }
    renderHistory();
}

function renderHistory() {
    const list = document.getElementById('historyList');

    if (scanHistory.length === 0) {
        list.innerHTML = '<div class="empty-history" id="emptyHistory">No scans yet — your checks will appear here.</div>';
        return;
    }

    list.innerHTML = scanHistory.map(entry => `
        <div class="history-item">
            <div class="history-left">
                <div class="history-input">${escapeHtml(entry.input)}</div>
                <div class="history-time">${entry.time}</div>
            </div>
            <div class="history-badge badge-${entry.color}">${entry.verdict}</div>
        </div>
    `).join('');
}

function clearHistory() {
    scanHistory = [];
    renderHistory();
}
</script>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(debug=True)
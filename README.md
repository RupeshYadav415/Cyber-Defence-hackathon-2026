# Cyber-Defence-hackathon-2026
 
 ##  PhishGuard — Phishing URL & Email Risk Checker

> **Cyber Defence Innovation Hackathon 2026**
> Track 1: Phishing Detection and Awareness
> Team: **Learner Panal** | York St John University — London Campus



##  What is PhishGuard?

PhishGuard is a lightweight web-based tool that allows anyone to paste a suspicious URL or email/message text and instantly receive a clear, plain-English risk assessment — no technical knowledge required.

It was built to address a genuine gap: everyday users have no simple, accessible tool to check whether a link or message is a phishing attempt before they click.


##  The Problem

- **90%+** of data breaches start with a phishing email or link
- Most individuals have **zero** free tools to check a suspicious link before clicking
- Enterprise-grade email filtering exists  but not for everyday users, students, or small organizations


## ✅ Features

| Feature | Description |

| 🔗 URL Analysis | Checks for missing HTTPS, raw IP addresses, URL shorteners, look-alike brand domains, suspicious hyphens and number substitutions |
| 📧 Email / Message Analysis | Scans text for urgency phrases, manipulation tactics, excessive capitals and exclamation marks |
| 🎯 Risk Scoring | Transparent rule-based scoring → **Safe / Suspicious / Dangerous** verdict |
| 💡 Awareness Tips | Every scan includes a plain-English security tip to educate the user |
| 🕒 Scan History | Scrollable session log of all previous checks with timestamps |

---

## 🛠️ Tech Stack

- **Python 3** — backend logic and URL/text analysis engine
- **Flask** — lightweight web server
- **HTML / CSS / JavaScript** — single-page dashboard
- **Rule-Based Detection** — fully transparent if/else checks

---

##  How to Run

### 1. Clone the repository
```bash
git clone https://github.com/RupeshYadav415/Cyber-Defence-hackathon-2026.git
cd Cyber-Defence-hackathon-2026
```

### 2. Install dependencies
```bash
pip install flask
```

### 3. Run the app
```bash
python app.py
```

### 4. Open in your browser

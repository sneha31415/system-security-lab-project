# Project Plan: Web Application Firewall for SQLi & XSS Detection
### System Security — Web Application Security
---

## 1. What We Are Building (Overview)

We are building two things that work together:

1. **A vulnerable Flask web app** — a simple login + comment system that has NO protection. It talks to an SQLite database and deliberately accepts any input the user sends. This is our "victim" that we use to demonstrate real attacks.

2. **A WAF middleware module** — a Python class that wraps around the Flask app. Every HTTP request that comes in passes through the WAF before the app ever sees it. The WAF inspects, filters, and either allows or blocks the request.

The key insight: the vulnerable app does NOT know the WAF exists. The WAF sits between the browser and the app at the WSGI layer (the Python web server interface). This is exactly how real-world WAFs work — they are transparent to the application.

---

## 2. How the WAF Connects to the App (Technical Process)

### The WSGI Middleware Pattern

Flask (and all Python web frameworks) communicate with the web server via a standard called WSGI (Web Server Gateway Interface). Every request goes through a chain like this:

```
Browser → Web Server → WSGI App → Flask Route Handler → Database
```

A WSGI middleware is simply a Python class that wraps the app:

```
Browser → Web Server → [WAF Middleware → Flask Route Handler] → Database
```

Here is the actual mechanism:

```python
# This is waf/waf.py
class WAFMiddleware:
    def __init__(self, app):
        self.app = app  # the Flask app is stored inside the WAF

    def __call__(self, environ, start_response):
        # Every request comes through here FIRST
        request = Request(environ)

        # Run all detection checks
        threat = self.inspect(request)

        if threat:
            # Block the request — Flask app never sees it
            self.log_attack(request, threat)
            response = Response("Blocked: Malicious input detected.", status=403)
            return response(environ, start_response)

        # Safe — pass the request to the real Flask app
        return self.app(environ, start_response)
```

```python
# This is app.py
from flask import Flask
from waf.waf import WAFMiddleware

app = Flask(__name__)

# Wrapping: the WAF takes the app as input
app.wsgi_app = WAFMiddleware(app.wsgi_app)
```

That single line `app.wsgi_app = WAFMiddleware(app.wsgi_app)` is all it takes to activate the WAF. To disable it (for demonstrating unprotected attacks), you comment it out.

### What the WAF Inspects

The WAF checks all of the following from every incoming request:
- GET parameters (URL query strings)
- POST body data (form submissions)
- Cookies
- HTTP headers (User-Agent, Referer, etc.)

---

## 3. Folder Structure

```
waf_project/
│
├── app.py                  # Main Flask app entry point
├── config.py               # Config flags (WAF on/off, debug mode, etc.)
├── requirements.txt        # All Python dependencies
├── README.md               # How to run the project
│
├── waf/                    # The WAF module (our core work)
│   ├── __init__.py
│   ├── waf.py              # Main WAFMiddleware class
│   ├── patterns.py         # SQLi and XSS signature patterns list
│   ├── sanitiser.py        # Input sanitisation functions
│   ├── blacklist.py        # Keyword blacklist engine
│   └── logger.py           # Attack logging to file
│
├── app_core/               # The vulnerable Flask application
│   ├── __init__.py
│   ├── routes.py           # URL route handlers
│   ├── database.py         # SQLite DB setup and queries (intentionally unsafe)
│   └── models.py           # Data models
│
├── templates/              # HTML pages
│   ├── index.html          # Home page
│   ├── login.html          # Login form (SQLi target)
│   ├── comments.html       # Comments page (XSS target)
│   ├── dashboard.html      # Logged-in user area
│   └── blocked.html        # WAF block page shown to attacker
│
├── static/                 # CSS and JS
│   └── style.css
│
├── logs/                   # Auto-created at runtime
│   └── attacks.log         # All detected attacks recorded here
│
├── tests/                  # Test scripts
│   ├── test_sqli.py        # Fires known SQLi payloads, checks detection
│   ├── test_xss.py         # Fires known XSS payloads, checks detection
│   ├── test_legit.py       # Fires legitimate inputs, checks no false positives
│   └── payloads/
│       ├── sqli_payloads.txt   # List of attack strings to test with
│       └── xss_payloads.txt
│
└── demo/
    └── demo_script.md      # Step-by-step lab exam demo instructions
```

---

## 4. Tech Stack

| Component | Technology | Why |
|---|---|---|
| Web framework | Python / Flask | Lightweight, easy middleware support |
| Database | SQLite | Zero setup, file-based, perfect for demo |
| WAF layer | Pure Python (Werkzeug) | No external WAF library — we build it ourselves |
| Pattern matching | Rabin-Karp (custom) | From the research paper, efficient string hashing |
| Testing | Python unittest + requests | Automate attack payload testing |
| Logging | Python logging module | Simple file-based attack logs |
| Frontend | HTML + Jinja2 templates | Basic forms to receive input |

**Python packages needed (requirements.txt):**
```
flask==3.0.0
werkzeug==3.0.0
requests==2.31.0        # for test scripts
```

That's it. No heavy dependencies. Everything runs locally with Python.

---

## 5. Implementation Plan (Phase by Phase)

---

### Phase 1 — Build the Vulnerable App (Week 1)

**Goal:** A working web app with a login page and a comments page that is completely unprotected.

**Files to build:**
- `app_core/database.py` — Create the SQLite database with a `users` table and a `comments` table. Insert 2–3 dummy users.
- `app_core/routes.py` — Create 3 routes:
  - `GET /` — home page
  - `POST /login` — takes username + password, queries DB using **unsafe string concatenation** (deliberately vulnerable)
  - `GET/POST /comments` — shows all comments and allows posting new ones (deliberately stores raw HTML)
- `templates/` — Build simple HTML forms for login and comments.

**The deliberately unsafe login query looks like this:**
```python
# app_core/database.py — INTENTIONALLY VULNERABLE
def check_login(username, password):
    conn = sqlite3.connect("database.db")
    # UNSAFE: directly concatenating user input into SQL
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    result = conn.execute(query).fetchone()
    return result
```

**Milestone:** You can open the app in a browser, type `' OR '1'='1` in the username field, and log in without a real password. You can also post `<script>alert('XSS')</script>` in the comments and see it execute.

---

### Phase 2 — Build the WAF Core (Week 2)

This is the main engineering work. Build the three detection layers.

#### Layer 1: Pattern Matching (`waf/patterns.py` + `waf/waf.py`)

Define the signature list:

```python
# waf/patterns.py
SQLI_PATTERNS = [
    r"('\s*(or|and)\s*'?\d)",       # ' OR '1
    r"(--\s*$)",                     # SQL comment --
    r"(;\s*drop\s+table)",           # ; DROP TABLE
    r"(union\s+select)",             # UNION SELECT
    r"(select\s+.*\s+from)",         # SELECT ... FROM
    r"(insert\s+into)",              # INSERT INTO
    r"(xp_cmdshell)",                # SQL Server shell
    r"(waitfor\s+delay)",            # Time-based blind SQLi
]

XSS_PATTERNS = [
    r"(<script[\s\S]*?>[\s\S]*?<\/script>)",  # <script> tags
    r"(javascript\s*:)",                       # javascript: URLs
    r"(on\w+\s*=)",                            # onerror=, onclick=, etc.
    r"(<iframe[\s\S]*?>)",                     # iframes
    r"(<img[^>]+src\s*=\s*['\"]?javascript)",  # img with JS src
    r"(eval\s*\()",                            # eval()
    r"(document\.cookie)",                     # cookie theft
]
```

The Rabin-Karp check function:

```python
# waf/waf.py (inside WAFMiddleware)
import re
from .patterns import SQLI_PATTERNS, XSS_PATTERNS

def _rabin_karp_match(self, text, patterns):
    """Check input text against all patterns using hash-based matching."""
    text_lower = text.lower()
    for pattern in patterns:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return pattern  # return which pattern matched
    return None
```

#### Layer 2: Input Sanitiser (`waf/sanitiser.py`)

```python
# waf/sanitiser.py
import html
import urllib.parse

def sanitise(value):
    """Decode encoded payloads then escape dangerous characters."""
    # Step 1: URL-decode (%3Cscript%3E → <script>)
    decoded = urllib.parse.unquote(value)
    # Step 2: HTML-decode (&lt;script&gt; → <script>)
    decoded = html.unescape(decoded)
    # Step 3: Escape back safely
    safe = html.escape(decoded, quote=True)
    return safe, decoded  # return both for pattern checking on decoded version
```

#### Layer 3: Blacklist Engine (`waf/blacklist.py`)

```python
# waf/blacklist.py
SQL_KEYWORDS = [
    "select", "insert", "update", "delete", "drop", "create",
    "alter", "exec", "execute", "union", "having", "group by",
    "order by", "--", "xp_", "sp_", "0x"
]

HTML_KEYWORDS = [
    "<script", "</script>", "javascript:", "vbscript:", "<iframe",
    "onerror=", "onload=", "onclick=", "eval(", "document.cookie",
    "window.location", "alert("
]

def blacklist_check(value):
    """Check if the value contains any blacklisted keyword."""
    lower = value.lower()
    for kw in SQL_KEYWORDS + HTML_KEYWORDS:
        if kw in lower:
            return kw  # return the keyword that triggered
    return None
```

#### Putting It Together (`waf/waf.py`)

```python
# waf/waf.py — full WAFMiddleware class
from werkzeug.wrappers import Request, Response
from .sanitiser import sanitise
from .blacklist import blacklist_check
from .logger import log_attack
from . import patterns
import re

class WAFMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        request = Request(environ)
        threat = self._inspect_request(request)

        if threat:
            log_attack(request, threat)
            res = Response(
                f"<h2>403 Forbidden</h2><p>Malicious input blocked.<br>Reason: {threat['reason']}</p>",
                status=403, mimetype="text/html"
            )
            return res(environ, start_response)

        return self.app(environ, start_response)

    def _inspect_request(self, request):
        """Run all inputs through all 3 layers."""
        # Collect all user inputs
        inputs = {}
        inputs.update(request.args.to_dict())     # GET params
        inputs.update(request.form.to_dict())     # POST form data

        for field, value in inputs.items():
            if not value:
                continue

            # Layer 1: Pattern matching on raw input
            match = self._pattern_check(value)
            if match:
                return {"field": field, "value": value, "reason": f"Pattern match: {match}", "layer": 1}

            # Layer 2: Decode and sanitise, then re-check
            safe_value, decoded = sanitise(value)
            if decoded != value:  # something was encoded — check the decoded version too
                match = self._pattern_check(decoded)
                if match:
                    return {"field": field, "value": value, "reason": f"Encoded payload: {match}", "layer": 2}

            # Layer 3: Blacklist check
            kw = blacklist_check(value)
            if kw:
                return {"field": field, "value": value, "reason": f"Blacklisted keyword: {kw}", "layer": 3}

        return None  # all clear

    def _pattern_check(self, value):
        lower = value.lower()
        for p in patterns.SQLI_PATTERNS + patterns.XSS_PATTERNS:
            if re.search(p, lower, re.IGNORECASE):
                return p
        return None
```

**Milestone:** Import and test the WAF in isolation. Pass it known attack strings and confirm they are caught. Pass it normal strings and confirm they pass through.

---

### Phase 3 — Connect WAF to App + Logging (Week 3)

**Connect:**
```python
# app.py
from flask import Flask
from app_core.routes import register_routes
from waf.waf import WAFMiddleware

app = Flask(__name__)
register_routes(app)

# ONE LINE to enable the WAF
app.wsgi_app = WAFMiddleware(app.wsgi_app)

if __name__ == "__main__":
    app.run(debug=True)
```

**Logging (`waf/logger.py`):**
```python
import logging
from datetime import datetime

logging.basicConfig(
    filename="logs/attacks.log",
    level=logging.WARNING,
    format="%(asctime)s | %(message)s"
)

def log_attack(request, threat):
    logging.warning(
        f"ATTACK BLOCKED | IP: {request.remote_addr} | "
        f"Path: {request.path} | Field: {threat['field']} | "
        f"Layer: {threat['layer']} | Reason: {threat['reason']} | "
        f"Payload: {threat['value'][:100]}"
    )
```

**Sample log output:**
```
2024-03-15 14:32:01 | ATTACK BLOCKED | IP: 127.0.0.1 | Path: /login | Field: username | Layer: 1 | Reason: Pattern match: (union\s+select) | Payload: ' UNION SELECT * FROM users--
```

**Milestone:** Run the app, fire an attack, see it in the log file in real time.

---

### Phase 4 — Testing (Week 3–4)

**Create automated test scripts:**

```python
# tests/test_sqli.py
import requests

BASE = "http://127.0.0.1:5000"

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' UNION SELECT username, password FROM users--",
    "1; DROP TABLE users--",
    "admin'--",
    "' OR 1=1#",
    "1' AND SLEEP(5)--",   # time-based blind
]

def test_sqli_detection():
    passed = 0
    failed = 0
    for payload in SQLI_PAYLOADS:
        r = requests.post(f"{BASE}/login", data={"username": payload, "password": "x"})
        if r.status_code == 403:
            print(f"[BLOCKED] {payload[:50]}")
            passed += 1
        else:
            print(f"[MISSED]  {payload[:50]}")
            failed += 1
    print(f"\nDetection rate: {passed}/{passed+failed} = {100*passed/(passed+failed):.0f}%")

test_sqli_detection()
```

Run similar tests for XSS and for legitimate inputs (to measure false positives).

**What to measure and record:**

| Metric | How to measure |
|---|---|
| Detection rate | (attacks caught / total attacks) × 100 |
| False positive rate | (legit inputs blocked / total legit inputs) × 100 |
| Response time | `time curl http://localhost:5000/login` with and without WAF |
| Coverage | Which attack variants are caught vs missed |

---

### Phase 5 — Demo Preparation (Week 4)

Build `demo/demo_script.md` with exact step-by-step instructions for the lab exam so any team member can present it.

**Demo flow:**

1. Start app with WAF **disabled** (comment out the middleware line)
2. Open browser → go to login page → type `' OR '1'='1` → log in successfully (breach shown)
3. Go to comments → post `<script>alert('XSS!')</script>` → alert pops (breach shown)
4. Stop app. Enable WAF (uncomment the line). Restart.
5. Repeat same attacks → both return 403 Blocked page
6. Open `logs/attacks.log` → show the logged entries
7. Run `tests/test_legit.py` → show normal users are unaffected

---

## 6. Summary Timeline

| Week | What gets done |
|---|---|
| Week 1 | Vulnerable Flask app working, attacks demonstrable without WAF |
| Week 2 | WAF module built: all 3 layers coded and unit-tested in isolation |
| Week 3 | WAF integrated into app, logging working, manual testing done |
| Week 4 | Automated test scripts, metrics recorded, demo polished |

---

## 7. How the Research Paper Fits In

The paper by Disawal & Suman (2023) directly informs three parts of our implementation:

- **The Rabin-Karp algorithm** used in Layer 1 is taken directly from their WV-DPM methodology
- **The attack pattern taxonomy** (the list of SQLi/XSS signatures) is based on their Table 1 and Table 2
- **The evaluation metrics** (detection rate, false positives, comparison with existing techniques) mirror their experimental methodology, allowing us to benchmark our results against theirs

In the abstract and in the report, you cite the paper as the basis for the detection methodology and compare your results to their reported numbers.

---

## 8. Things to Watch Out For

**Avoid over-blocking.** The blacklist keyword `select` would block a username like "selected" or a comment saying "I selected this option." Use regex word boundaries (`\bselect\b`) rather than plain substring matching where possible.

**URL encoding bypass.** Attackers encode `<script>` as `%3Cscript%3E` to dodge simple checks. Our Layer 2 sanitiser handles this by decoding first, then checking.

**Case variation.** `SeLeCt` is still SQL. Always lowercase inputs before checking — the pattern matcher does this with `.lower()`.

**The demo environment matters.** Run everything on localhost. Do not deploy this online — the vulnerable app is intentionally insecure.

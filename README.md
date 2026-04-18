# Zero Trust Security Command Center

A **Next Generation Firewall** prototype that uses an AI security engine (OpenAI) to classify HTTP traffic, assign risk scores, and block or allow requests. Built with Node.js, Express, and SQLite.

**Status:** Active | **Platform:** Windows, Linux, macOS | **Node:** >= 14.0

---

## Overview

The system sits between clients and an application server. Every request passes through a **Zero Trust** pipeline: blocked-IP check, rate limiting, and an **AI Security Engine** that classifies the request (allow / suspicious / block) and assigns a risk score. No regex rules—the LLM is the decision maker.

### Features

- **AI Security Engine** — OpenAI classifies requests; returns risk score (0–1), attack type, severity, and reason. Fail-closed on API errors.
- **Zero Trust pipeline** — Blocked IP check, rate limiter (100 req/min per IP), AI classification, traffic logging, then proxy to app.
- **Automated response** — High-severity blocks can auto-block the client IP (localhost exempt for testing).
- **Dashboard** — Overview stats, charts (traffic, attack types, risk timeline, severity, top IPs), Traffic Logs as clickable cards with risk meter, Intrusion Logs, Threats, Audit Logs, Blocked IPs. Download CSV for each log type. Light/dark theme.
- **Test modal** — Built-in test commands: low-risk (expected allow) and attack categories (SQL injection, XSS, command injection, path traversal, LDAP/NoSQL/SSRF, etc.). Run from the UI and see results in Traffic Logs.
- **SQLite storage** — Traffic, intrusions, audit, and blocked IPs in `database/logs.db`.

---

## What's included (all updates)

Everything that was built or changed in this project:

**Backend / pipeline**
- LLM-only security pipeline: no regex IDS, no rule engine; OpenAI is the single decision maker.
- Four-stage pipeline: blocked IP check → rate limiter → AI Security Engine → traffic logger → proxy.
- `aiSecurityEngine.js` — Decides when to call the LLM (query params, `/login`, body, high rate); otherwise allows with low risk (0.05).
- `openaiClient.js` — Builds prompt, calls OpenAI, normalizes JSON; **fail-closed** on API errors (block request with high risk).
- Minimum low risk score: allowed requests never show 0.00; backend uses at least 0.05 so the UI can show "low but not zero".
- Auto-block on high-severity blocks; localhost/127.0.0.1 exempt so testing does not lock you out.
- `.env` and `dotenv` for `OPENAI_API_KEY`; optional `.env.example`.

**Dashboard UI**
- Rebranded as **Zero Trust Security Command Center** (no AI/LLM/OpenAI wording in the UI).
- **Sidebar navigation** — Six pages: Overview, Traffic Logs, Intrusion Logs, Threats, Audit Logs, Blocked IPs (no tabs; one page at a time).
- **Traffic Logs as cards** — Each request is a card with prominent risk score and a horizontal risk meter (0–100%). Click to expand and see full endpoint, analysis text, larger risk meter, and details (IP, method, action, time).
- **Overview page** — Six stat cards (total requests, blocked, intrusions, blocked IPs, threats, avg risk), engine bar (“Zero Trust Engine”), and charts: Traffic, Attack Types, Threat Timeline, Request Trends, Severity, High Risk IPs.
- **Download CSV** — Button on Traffic Logs, Intrusion Logs, Threats, and Audit Logs; fetches data and downloads a date-stamped CSV (UTF-8, proper escaping).
- **Test modal** — “Test” button in the top bar opens a modal with all test commands: **Low risk** (5 requests, expected 200), **SQL injection** (7), **XSS** (8), **Command injection** (8), **Path traversal / LFI** (4), **Other** (LDAP, NoSQL, SSRF, open redirect, CRLF, XML). Each row has a “Run” button that sends the request from the frontend and shows the status code (200 / 403). 403 on attacks = firewall blocked (expected).
- **Consistent font** — DM Sans used everywhere (dashboard and login); no emoji; separators use `|` instead of bullets.
- **Favicon** — Inline SVG shield favicon on dashboard and login so the browser does not request `/favicon.ico` (no 404).
- **Login page** — Zero Trust branding, SVG lock icon instead of emoji, password toggle “Show” / “Hide” (no emoji), same DM Sans and theme variables.
- **Light/dark theme** — Toggle in the dashboard header; preference stored in `localStorage`.

**Data and config**
- No hardcoded log data: traffic, intrusions, audit, and blocked IPs are written only at runtime. Database path and schema are in code; `threatIntel.json` is optional reference data (not used in the active pipeline).
- Stats and charts use the same APIs; dashboard auto-refreshes every 5 seconds.

**Docs**
- This README: overview, architecture, structure, quick start, usage, APIs, config, database, tech stack, and this “What’s included” list.

---

## Architecture

```
  Client
    |
    v
  Firewall (port 4000)
    1. Blocked IP check
    2. Rate limiter
    3. AI Security Engine (OpenAI)
    4. Traffic logger
    5. Proxy to app (if allowed)
    |
    v
  Application server (port 5000)
    |
    v
  SQLite (database/logs.db)
```

| Component            | Port | Description                          |
|----------------------|------|--------------------------------------|
| Firewall server      | 4000 | Entry point, dashboard, API, proxy   |
| Application server  | 5000 | Protected app (`/`, `/api/data`, `/login`, `/admin`) |

---

## Zero Trust Security Model

The system implements a **Zero Trust Network Security Model** where every request is evaluated before access is granted.

Unlike traditional perimeter firewalls, the system assumes **no implicit trust** and applies contextual security analysis to each request.

**Zero Trust principles implemented:**

- **Continuous verification** — Every HTTP request is evaluated by the pipeline (blocked IP, rate limit, AI engine); no request is trusted by default.
- **Context-aware AI risk scoring** — The AI Security Engine receives full context and returns a risk score (0–1) plus attack type, severity, and reason.
- **Dynamic security decisioning** — Per-request decision: **allow**, **suspicious** (allow but logged), or **block**. No static allow-lists for application paths; the LLM decides based on payload and behavior.
- **Automated incident response** — High-severity blocks trigger automatic IP blocking and audit logging (localhost exempt for testing).
- **Comprehensive telemetry** — Every request is logged with IP, method, endpoint, action, risk score, attack type, severity, and AI analysis; dashboard and CSV export for all log types.

**Context sent to the AI engine:**

- Client IP and request rate (requests per minute)
- HTTP method and full endpoint (path + query)
- Query parameters and request body
- Headers (user-agent, referer, content-type)

The engine returns **decision** (allow / suspicious / block), **risk_score** (0–1), **attack_type**, **severity**, and **reason**. The firewall enforces the decision and logs it; blocked requests never reach the application server.

---

## Project structure

```
firewall-project/
  app/
    appServer.js              # Application server (5000)
  backend/
    firewallServer.js         # Firewall entry (4000), dashboard, APIs
    firewallMiddleware.js     # Pipeline: blocked IP, rate limit, AI engine, logger
    aiSecurityEngine.js       # When to call LLM, context builder
    openaiClient.js           # OpenAI API, prompt, response normalization
    database.js               # SQLite (traffic_logs, intrusion_logs, audit_logs, blocked_ips)
    threatIntel.json          # Optional threat data (not in active pipeline)
  dashboard/
    index.html                # Command center UI (sidebar, pages, charts, test modal)
    login.html                # Login page
    style.css                 # Shared styles (DM Sans, no emoji)
    script.js                 # Data fetch, charts, CSV export, test runner
  database/
    logs.db                   # SQLite DB (auto-created)
  .env                        # OPENAI_API_KEY (optional; if missing, suspicious requests still get a decision)
  package.json
  README.md
```

---

## Quick start

### Prerequisites

- Node.js 14+
- npm

### Install and run

```bash
cd firewall-project
npm install
```

**Terminal 1 — application server:**

```bash
node app/appServer.js
```

**Terminal 2 — firewall:**

```bash
node backend/firewallServer.js
```

**Dashboard:** [http://localhost:4000/dashboard](http://localhost:4000/dashboard)  
(Login with any email; no real auth.)

### Optional: OpenAI

1. Copy `.env.example` to `.env` (or create `.env`).
2. Set `OPENAI_API_KEY=sk-...` in `.env`.
3. Restart the firewall server.

With a valid key, the AI engine classifies suspicious requests (e.g. with query params or `/login`). Without it, the engine still returns decisions (fail-closed on errors for requests that were sent to the AI).

---

## Usage

### Dashboard

- **Overview** — Stats (total requests, blocked, intrusions, blocked IPs, threats, avg risk), engine bar, charts.
- **Traffic Logs** — One card per request; risk score and meter. Click a card for full details (endpoint, analysis, risk meter).
- **Intrusion Logs / Threats / Audit Logs / Blocked IPs** — Tables with **Download CSV**.
- **Test** (top bar) — Modal with low-risk and attack test commands. Click **Run** to send the request; check Traffic Logs for the result. 403 on attack tests means the firewall blocked as expected.

### Sending traffic through the firewall

- Normal: `http://localhost:4000/proxy/`, `http://localhost:4000/proxy/api/data`, `http://localhost:4000/login`
- Attack examples (expected block):  
  `http://localhost:4000/login?user=' OR 1=1--`  
  `http://localhost:4000/api/data?cmd=| whoami`

Use the Test modal in the dashboard to run many variants (SQL, XSS, command injection, path traversal, etc.) from the browser.

---

## API endpoints (firewall)

| Method | Path                   | Description                |
|--------|------------------------|----------------------------|
| GET    | /api/stats             | Overview stats             |
| GET    | /api/traffic-logs      | All traffic with risk data|
| GET    | /api/intrusion-logs    | Intrusion entries          |
| GET    | /api/ai-threat-logs    | AI-flagged traffic        |
| GET    | /api/audit-logs        | Audit entries              |
| GET    | /api/blocked-ips       | Blocked IP list            |
| DELETE | /api/blocked-ips/:id   | Unblock an IP              |
| GET    | /api/risk-metrics      | Risk timeline, attack dist.|
| GET    | /api/top-attackers     | IPs by risk / blocked      |

---

## Configuration

- **Ports** — Firewall: `backend/firewallServer.js` (`PORT`). App: `app/appServer.js`.
- **Rate limit** — `backend/firewallMiddleware.js`: `RATE_LIMIT_MAX` (default 100/min per IP).
- **OpenAI** — `.env`: `OPENAI_API_KEY`. Model and behavior: `backend/openaiClient.js`.

---

## Database

SQLite file: `database/logs.db` (created on first run).

- **traffic_logs** — id, ip, method, endpoint, action, risk_score, attack_type, severity, ai_reason, ai_decision, timestamp  
- **intrusion_logs** — id, ip, attack_type, endpoint, severity, timestamp  
- **audit_logs** — id, action, timestamp  
- **blocked_ips** — id, ip, reason, timestamp  

---

## Tech stack

- Node.js, Express
- SQLite (sql.js)
- OpenAI API (optional)
- Vanilla JS dashboard (DM Sans, Chart.js for charts)
- dotenv for `.env`

---

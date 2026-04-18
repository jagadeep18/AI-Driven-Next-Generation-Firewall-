# AI-NGFW Security Command Center — Project Documentation

**Next Generation Firewall with AI Threat Detection Engine**
Status: **ACTIVE** · Platform: **Windows | Linux | Mac** · Node: **>=14.0**

---

## 1. What We Built

An **AI-Powered Next Generation Firewall (NGFW)** prototype that upgrades a traditional firewall monitoring system with:

- **AI Threat Detection Engine** — LLM-assisted analysis (OpenAI GPT or local heuristic fallback) that classifies requests, assigns risk scores, and generates human-readable threat reasons.
- **Zero Trust Risk Engine** — Context-aware risk scoring that combines 5 weighted signals (AI analysis, threat intel, request rate, endpoint sensitivity, login frequency) to make allow/suspicious/block decisions.
- **Threat Intelligence Module** — Loaded from a local JSON feed with malicious IPs, Tor exit nodes, known scanners, and malicious domains. Each IP gets a reputation score.
- **Automated Incident Response** — High-severity threats trigger automatic IP blocking and audit logging. Localhost IPs are exempt from auto-blocking for safe testing.
- **Advanced Security Analytics Dashboard** — Rebranded "AI-NGFW Security Command Center" with 6 stat cards, 6 charts, AI banner, and a dedicated AI Threats tab.

All existing functionality (traffic logs, intrusion logs, audit logs, blocked IPs, rate limiting, access policies, proxy routing) is preserved and enhanced.

---

## 2. Architecture

| Component | Port | Role |
|-----------|------|------|
| **Firewall Server** | **4000** | Entry point. Runs AI-NGFW pipeline, serves dashboard, proxies to app. |
| **Application Server** | **5000** | Protected backend. `/`, `/api/data`, `/login`, `/admin`. |

```
  Client (browser / API)
         │
         ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  AI-NGFW SECURITY COMMAND CENTER (port 4000)                    │
  │  ┌───────────────────────────────────────────────────────────┐  │
  │  │  1. Blocked IP Check                                      │  │
  │  │  2. Rate Limiter (100 req/min per IP)                     │  │
  │  │  3. Threat Intelligence Check  ← threatIntel.json         │  │
  │  │  4. Access Policy Enforcement                             │  │
  │  │  5. AI Security Pipeline                                  │  │
  │  │     ├─ Legacy IDS (regex patterns)                        │  │
  │  │     ├─ LLM Threat Analyzer (OpenAI or Local AI)           │  │
  │  │     └─ Zero Trust Risk Engine (composite risk → decision) │  │
  │  │  6. Traffic Logger (with AI risk data)                    │  │
  │  └───────────────────────────────────────────────────────────┘  │
  │                                                                 │
  │  Dashboard: /dashboard (login, charts, tabs, AI metrics)        │
  │  APIs: /api/stats, /api/traffic-logs, /api/ai-threat-logs, etc. │
  └──────────────────────┬──────────────────────────────────────────┘
                         │ (if ALLOWED)
                         ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  APPLICATION SERVER (port 5000)                                 │
  └──────────────────────┬──────────────────────────────────────────┘
                         ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  SQLite (database/logs.db) — sql.js                             │
  │  traffic_logs (+ risk_score, attack_type, severity, ai_reason)  │
  │  intrusion_logs, audit_logs, blocked_ips                        │
  └─────────────────────────────────────────────────────────────────┘
```

---

## 3. Project Structure

| Path | Purpose |
|------|---------|
| **app/appServer.js** | Express app (port 5000). Endpoints: `/`, `/api/data`, `/login`, `/admin`. |
| **backend/firewallServer.js** | Main AI-NGFW server (port 4000). Dashboard, APIs, pipeline, proxy. |
| **backend/firewallMiddleware.js** | 6-stage middleware pipeline including new AI stages. |
| **backend/intrusionDetector.js** | Legacy regex-based IDS (20+ patterns). Used inside AI pipeline. |
| **backend/llmThreatAnalyzer.js** | **NEW** — AI threat analysis. OpenAI GPT or local heuristic engine. |
| **backend/zeroTrustEngine.js** | **NEW** — Zero Trust risk scoring with 5 weighted signals. |
| **backend/threatIntel.js** | **NEW** — Threat intelligence module (loads JSON feed). |
| **backend/threatIntel.json** | **NEW** — Threat data: 15 malicious IPs, 8 domains, Tor nodes, scanners. |
| **backend/database.js** | SQLite via sql.js. Enhanced with AI columns and new query functions. |
| **dashboard/index.html** | AI-NGFW Security Command Center UI. |
| **dashboard/login.html** | Login page (rebranded). |
| **dashboard/style.css** | Styles including AI banner, risk badges, new card variants. |
| **dashboard/script.js** | Dashboard logic: 6 charts, 5 tabs, AI data fetching, auto-refresh. |
| **database/logs.db** | SQLite DB file (auto-created). |
| **package.json** | Dependencies: express, sql.js, http-proxy-middleware, cors. |

---

## 4. AI-NGFW Security Pipeline

Every request through the firewall passes these 6 stages in order:

| # | Stage | Module | Action |
|---|-------|--------|--------|
| 1 | **Blocked IP Check** | firewallMiddleware.js | If IP is in `blocked_ips` → 403, log, stop. |
| 2 | **Rate Limiter** | firewallMiddleware.js | 100 req/min per IP. Exceeded → 429. Auto-block after 150+. Exposes `req.rateCount` for ZT engine. |
| 3 | **Threat Intel Check** | threatIntel.js | Checks IP against threat feeds. Flags and sets `req.threatIntel` with reputation score. |
| 4 | **Access Policy** | firewallMiddleware.js | `/admin` blocked, `/api/`, `/login`, `/` allowed. First match wins. |
| 5 | **AI Security Pipeline** | llmThreatAnalyzer.js + intrusionDetector.js + zeroTrustEngine.js | Runs legacy IDS → AI analyzer → Zero Trust decision. Blocks if IDS detects or ZT score > 0.75. Logs suspicious if 0.4–0.75. Auto-blocks IPs on high severity (localhost exempt). |
| 6 | **Traffic Logger** | firewallMiddleware.js | Logs ALLOWED requests with risk_score, attack_type, severity, ai_reason. |

---

## 5. New Modules (What They Do)

### 5.1 LLM Threat Analyzer (`llmThreatAnalyzer.js`)

**Dual-mode AI engine:**

- **OPENAI mode**: If `OPENAI_API_KEY` env var is set and `openai` npm package is installed, sends suspicious requests to GPT-3.5-turbo for classification. Uses a prompt that returns structured JSON.
- **LOCAL mode** (default): Sophisticated heuristic engine with weighted pattern scoring across SQL injection (8 patterns), XSS (8 patterns), and command injection (6 patterns). Produces risk scores, attack classifications, and human-readable reasons identical in format to OpenAI output.

**Smart filtering**: Only deeply analyzes requests that show suspicious indicators (query params with special chars, login attempts, POST with body, encoded chars, long URLs, attack keywords). Non-suspicious requests get `risk_score: 0.05`.

**Output format**:
```json
{
  "threat": true,
  "attack_type": "SQL_INJECTION",
  "severity": "high",
  "risk_score": 0.92,
  "reason": "Boolean-based SQL injection pattern detected"
}
```

### 5.2 Zero Trust Risk Engine (`zeroTrustEngine.js`)

Combines 5 weighted signals into a composite risk score (0.0–1.0):

| Signal | Weight | Source |
|--------|--------|--------|
| AI Threat Analysis | 40% | LLM analyzer risk_score |
| Threat Intelligence | 25% | IP reputation from threat feeds |
| Request Rate | 15% | Current req/min for this IP |
| Endpoint Sensitivity | 10% | /admin=0.4, /login=0.15, /api=0.05 |
| Login Frequency | 10% | Login attempts in last 5 min |

**Decision thresholds**:
- `risk < 0.40` → **ALLOW**
- `0.40 – 0.75` → **SUSPICIOUS** (allowed but logged)
- `risk > 0.75` → **BLOCK**
- Override: AI detected high-severity threat → forced **BLOCK**

### 5.3 Threat Intelligence (`threatIntel.js` + `threatIntel.json`)

Loads a local JSON feed with:
- 15 malicious IP addresses
- 8 malicious domains
- 7 Tor exit node IPs
- 5 known scanner IPs
- 4 threat feed metadata entries (AbuseIPDB, AlienVault OTX, etc.)

`checkIP(ip)` returns `{ malicious, categories, reputation_score }`. Score is additive: malicious_ip (+0.5), tor_exit (+0.3), scanner (+0.2), capped at 1.0.

### 5.4 Automated Response

Built into `firewallMiddleware.js`:
- IDS detects HIGH severity attack → auto-block the IP
- Zero Trust engine blocks with high severity AI result → auto-block the IP
- Localhost IPs (`127.0.0.1`, `::1`) are exempt from auto-blocking
- Every auto-block generates an audit log entry

---

## 6. Database Schema

### traffic_logs (enhanced)

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment |
| ip | TEXT | Source IP |
| method | TEXT | HTTP method |
| endpoint | TEXT | URL path |
| action | TEXT | ALLOW or BLOCK |
| **risk_score** | **REAL** | **AI risk score 0.0–1.0** |
| **attack_type** | **TEXT** | **SQL_INJECTION, XSS, COMMAND_INJECTION, Normal** |
| **severity** | **TEXT** | **low, medium, high** |
| **ai_reason** | **TEXT** | **Human-readable AI explanation** |
| timestamp | TEXT | Date/time |

### intrusion_logs, audit_logs, blocked_ips
Same as before (see original documentation).

---

## 7. API Endpoints

### Existing (enhanced)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/stats` | Now includes `aiThreatsDetected`, `avgRiskScore`, `aiEngineMode` |
| GET | `/api/traffic-logs` | Now includes risk_score, attack_type, severity, ai_reason columns |
| GET | `/api/intrusion-logs` | Unchanged |
| GET | `/api/audit-logs` | Unchanged |
| GET | `/api/blocked-ips` | Unchanged |
| DELETE | `/api/blocked-ips/:id` | Unchanged |

### New

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/ai-threat-logs` | Traffic logs flagged by AI (risk > 0.3 or attack_type set) |
| GET | `/api/risk-metrics` | avgRiskScore, maxRiskScore, aiThreatsDetected, threatIntelHits, riskTimeline, attackTypeDistribution |
| GET | `/api/top-attackers` | IPs ranked by avg risk score with blocked counts |
| GET | `/api/threat-intel-stats` | Threat feed summary (counts, feed names) |

---

## 8. Dashboard (AI-NGFW Security Command Center)

### Rebranded Header
- Title: **AI-NGFW Security Command Center**
- Subtitle: *AI Threat Engine • Zero Trust Architecture • Real-Time Analytics*
- Status badge: **AI-NGFW ACTIVE**

### AI Security Banner
Shows three status pills:
- **Engine**: LOCAL AI (or OPENAI)
- **Threat Intel**: ACTIVE
- **Zero Trust**: ENFORCED

### 6 Stat Cards
1. Total Requests
2. Blocked Requests
3. Intrusion Attempts
4. Blocked IPs
5. **AI Threats Detected** (new)
6. **Avg Risk Score** (new)

### 6 Charts
1. Traffic Status (doughnut — allowed vs blocked)
2. Attack Type Distribution (horizontal bar — driven by real data)
3. Risk Score Timeline (line — real-time risk scores)
4. Request Trends (line — total vs blocked over time)
5. Threat Severity (radar — high/medium/low)
6. Top Attacking IPs (horizontal bar — by avg risk)

### 5 Tabs
1. Traffic Logs — now shows Risk and AI Analysis columns
2. Intrusion Logs — unchanged
3. **AI Threats** (new) — filtered view of AI-flagged traffic with risk_score, attack_type, severity, ai_reason
4. Audit Logs — unchanged
5. Blocked IPs — unchanged

### Login Page (Rebranded)
- Title: AI-NGFW Security Command Center
- Features listed: AI Threat Engine, Zero Trust Architecture, Threat Intelligence Feed

---

## 9. Quick Start

```bash
cd firewall-project
npm install

# Terminal 1
node app/appServer.js

# Terminal 2
node backend/firewallServer.js
```

Dashboard: **http://localhost:4000/dashboard**

### Optional: Enable OpenAI

```bash
npm install openai
set OPENAI_API_KEY=sk-your-key-here
node backend/firewallServer.js
```

The system works fully without OpenAI using the local AI heuristic engine.

---

## 10. Testing

```powershell
# Legitimate (should pass, risk ~0.05)
Invoke-RestMethod http://localhost:4000/proxy/api/data

# SQL Injection (blocked, risk ~0.38)
Invoke-RestMethod "http://localhost:4000/proxy/login?user=%27%20OR%201=1--"

# XSS (blocked, risk ~0.37)
Invoke-RestMethod "http://localhost:4000/proxy/api/data?q=%3Cscript%3Ealert(1)%3C/script%3E"

# Command Injection (blocked, risk ~0.37)
Invoke-RestMethod "http://localhost:4000/proxy/api/data?cmd=;cat%20/etc/passwd"

# Admin Access (blocked by policy)
Invoke-RestMethod http://localhost:4000/proxy/admin
```

---

## 11. Configuration

| What | File | Variable |
|------|------|----------|
| Firewall port | `backend/firewallServer.js` | `PORT = 4000` |
| App server port | `app/appServer.js` | `PORT = 5000` |
| Rate limit | `backend/firewallMiddleware.js` | `RATE_LIMIT_MAX`, `RATE_LIMIT_WINDOW_MS` |
| Access policies | `backend/firewallMiddleware.js` | `ACCESS_POLICIES` array |
| Auto-block exemptions | `backend/firewallMiddleware.js` | `AUTOBLOCK_EXEMPT` set |
| Attack signatures | `backend/intrusionDetector.js` | `ATTACK_SIGNATURES` array |
| AI patterns | `backend/llmThreatAnalyzer.js` | `PATTERNS` object |
| Zero Trust weights | `backend/zeroTrustEngine.js` | `WEIGHTS` object |
| ZT decision thresholds | `backend/zeroTrustEngine.js` | Inline: 0.40, 0.75 |
| Threat intel data | `backend/threatIntel.json` | Edit JSON directly |
| Dashboard refresh | `dashboard/script.js` | `REFRESH_INTERVAL` |

---

## 12. Tech Stack

- **Runtime**: Node.js (14+)
- **Server**: Express
- **Database**: SQLite via sql.js (no native bindings)
- **Proxy**: http-proxy-middleware
- **AI**: OpenAI GPT-3.5-turbo (optional) + local heuristic engine
- **Dashboard**: Vanilla JS, HTML5, CSS3, Chart.js (CDN)
- **CORS**: cors middleware

---

## 13. Key Concepts Demonstrated

1. **AI-Assisted Threat Detection** — LLM integration for request classification
2. **Zero Trust Network Architecture** — Never trust, always verify with risk scoring
3. **Threat Intelligence** — IP reputation checking against curated feeds
4. **Automated Incident Response** — Auto-blocking with audit trail
5. **Context-Aware Security** — Combining multiple signals for decisions
6. **Defense in Depth** — Multiple security layers (IDS + AI + ZT + policies)
7. **Real-Time Security Analytics** — Live dashboard with risk visualisations
